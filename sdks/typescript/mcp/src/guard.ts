import { amap, AmapError, AmapErrorCode } from '@agentmandateprotocol/core'
import type { DelegationToken, VerificationResult, KeyResolver } from '@agentmandateprotocol/core'

/** Rule for a specific tool name. Use '*' as the key for a catch-all. */
export interface ToolRule {
  /** Permissions that must appear in the mandate's leaf token. */
  requires: string[]
  /** Per-tool mode override. Falls back to AmapGuardOptions.mode. */
  policy?: 'enforce' | 'audit' | 'warn'
}

export interface AuditEntry {
  /**
   * - `TOOL_ALLOWED`   — permission check passed; call proceeds.
   * - `TOOL_BLOCKED`   — permission check failed in `enforce` mode; call is thrown before reaching the server.
   * - `TOOL_VIOLATION` — permission check failed in `audit`/`warn` mode; call proceeds despite the failure.
   */
  event: 'TOOL_ALLOWED' | 'TOOL_BLOCKED' | 'TOOL_VIOLATION'
  tool: string
  timestamp: string
  /** tokenId of the root token */
  mandateId: string
  /** DID of the human who issued the root mandate */
  principal: string
  /** Present when event is TOOL_BLOCKED or TOOL_VIOLATION */
  reason?: string
}

export interface AmapGuardOptions {
  /** The mandate chain the agent is operating under. */
  mandate: DelegationToken[]
  /**
   * Enforcement mode.
   * - 'enforce' (default): blocked calls throw AmapError and never reach the server.
   * - 'audit': all calls go through; blocked calls are logged via onAudit.
   * - 'warn': same as audit — logs the violation but does not block.
   */
  mode?: 'enforce' | 'audit' | 'warn'
  /**
   * Per-tool rules. Key is the tool name; '*' is the catch-all.
   * If a tool has no matching rule and no catch-all, the tool name itself
   * is used as the required permission.
   */
  rules?: Record<string, ToolRule>
  /** Key resolver for mandate chain verification. */
  keyResolver?: KeyResolver
  /** Called for every tool call — allowed or blocked. Use for audit logging. */
  onAudit?: (entry: AuditEntry) => void
}

/** Any object with a callTool method — duck-typed so no SDK dependency is required. */
export interface McpClientLike {
  callTool(name: string, params: Record<string, unknown>): Promise<unknown>
}

/**
 * Client-side A-MAP guard. Wraps an MCP client and enforces mandate permissions
 * before any call reaches the server.
 *
 * ⚠️  CLIENT-SIDE ONLY — NOT a server-side security barrier.
 * `AmapGuard` verifies the mandate chain and checks permissions on the calling side,
 * preventing out-of-scope tool calls from ever being sent. It does NOT verify request
 * signatures, timestamps, or nonces. A malicious or compromised process that bypasses
 * this guard can still call the server directly.
 *
 * For server-side enforcement (the only cryptographically sound boundary), use
 * `amapProtect()` from `@agentmandateprotocol/mcp` on the tool handler.
 * `AmapGuard` and `amapProtect` are complementary: the guard gives the agent
 * early feedback; `amapProtect` is the authoritative check.
 *
 * Usage:
 *   const guarded = new AmapGuard(mcpClient, { mandate, rules, mode: 'enforce' })
 *   await guarded.callTool('filesystem/deleteFile', { path })
 *   // → throws PERMISSION_INFLATION if mandate lacks 'filesystem/deleteFile'
 *   // → MCP server never receives the call (client-side short-circuit only)
 */
export class AmapGuard {
  private verifiedMandate: VerificationResult | null = null
  private verifyPromise: Promise<VerificationResult> | null = null

  constructor(
    private readonly client: McpClientLike,
    private readonly options: AmapGuardOptions,
  ) {}

  private async getVerifiedMandate(): Promise<VerificationResult> {
    if (this.verifiedMandate !== null) return this.verifiedMandate
    if (this.verifyPromise === null) {
      this.verifyPromise = amap.verify({
        chain: this.options.mandate,
        ...(this.options.keyResolver !== undefined ? { keyResolver: this.options.keyResolver } : {}),
      })
    }
    this.verifiedMandate = await this.verifyPromise
    return this.verifiedMandate
  }

  private resolveRule(toolName: string): ToolRule {
    const rules = this.options.rules ?? {}
    return rules[toolName] ?? rules['*'] ?? { requires: [`tool:${toolName}`] }
  }

  async callTool(toolName: string, params: Record<string, unknown>): Promise<unknown> {
    const mandate = await this.getVerifiedMandate()
    const rule = this.resolveRule(toolName)
    const mode = rule.policy ?? this.options.mode ?? 'enforce'

    const leafToken = mandate.chain[mandate.chain.length - 1]!.token
    const missing = rule.requires.filter(p => !leafToken.permissions.includes(p))
    const allowed = missing.length === 0

    let event: AuditEntry['event']
    if (allowed) {
      event = 'TOOL_ALLOWED'
    } else if (mode === 'enforce') {
      event = 'TOOL_BLOCKED'
    } else {
      event = 'TOOL_VIOLATION'
    }

    const entry: AuditEntry = {
      event,
      tool: toolName,
      timestamp: new Date().toISOString(),
      mandateId: mandate.chain[0]!.token.tokenId,
      principal: mandate.principal,
      ...(allowed ? {} : { reason: `Missing permissions: ${missing.join(', ')}` }),
    }

    this.options.onAudit?.(entry)

    if (!allowed && mode === 'enforce') {
      throw new AmapError(
        AmapErrorCode.PERMISSION_INFLATION,
        `Tool "${toolName}" requires permissions not granted by mandate: ${missing.join(', ')}`,
      )
    }

    return this.client.callTool(toolName, params)
  }
}
