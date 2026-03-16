import { amap, AmapError, AmapErrorCode, evaluatePolicy } from '@agentmandateprotocol/core'
import type { KeyResolver, NonceStore, RevocationChecker } from '@agentmandateprotocol/core'
import type { SessionMandateStore } from './session-store.js'

export interface HookContext {
  sessionId: string
  toolName: string
}

export interface HookOptions {
  sessionStore: SessionMandateStore
  keyResolver?: KeyResolver
  nonceStore?: NonceStore
  revocationChecker?: RevocationChecker
}

interface AmapEnvelope {
  headers: Record<string, string>
  method?: string
  path?: string
}

/**
 * Before-Tool-Call hook. Called before every tool invocation.
 *
 * Resolution order:
 * 1. Per-call `_amap` envelope — extracts headers, calls verifyRequest() with a fresh
 *    nonce and request signature. Required for agent-to-agent delegation paths.
 *    Enforces: expiry, signature, chain, permissions, policy (deniedActions/allowedActions),
 *    parameterLocks, nonce replay.
 * 2. Session-scoped chain — uses the VerificationResult cached at registration.
 *    Enforces per-call: permission, policy (deniedActions/allowedActions), parameterLocks.
 * 3. Neither present — throws BROKEN_CHAIN.
 *
 * Returns clean input (without _amap) on success.
 * Throws AmapError on any auth failure.
 */
export async function beforeToolCall(
  input: Record<string, unknown>,
  ctx: HookContext,
  opts: HookOptions,
): Promise<Record<string, unknown>> {
  // Path 1: per-call _amap envelope (agent-to-agent)
  if (input['_amap'] !== undefined) {
    const envelope = input['_amap'] as AmapEnvelope
    const { _amap: _, ...cleanInput } = input

    const result = await amap.verifyRequest({
      headers: envelope.headers,
      method: envelope.method ?? 'POST',
      path: envelope.path ?? `/tool/${ctx.toolName}`,
      expectedPermission: `tool:${ctx.toolName}`,
      requestParams: cleanInput,          // enables parameterLock checking inside verifyRequest
      ...(opts.keyResolver !== undefined ? { keyResolver: opts.keyResolver } : {}),
      ...(opts.nonceStore !== undefined ? { nonceStore: opts.nonceStore } : {}),
      ...(opts.revocationChecker !== undefined ? { revocationChecker: opts.revocationChecker } : {}),
    })

    // Evaluate allow/deny policy using the verified effective constraints.
    // Not passed as requestedAction to verifyRequest because verify() throws on IMPLICIT_DENY
    // even when allowedActions is unset, which would block all unconstrained mandates.
    applyPolicyCheck(ctx.toolName, result.effectiveConstraints)

    return cleanInput
  }

  // Path 2: session-scoped chain (already verified at registration)
  const session = opts.sessionStore.get(ctx.sessionId)
  if (session === undefined) {
    throw new AmapError(
      AmapErrorCode.BROKEN_CHAIN,
      `No mandate registered for session "${ctx.sessionId}". ` +
        'Call amap_register_session first, or include _amap in each tool call.',
    )
  }

  // Re-check expiry — the mandate may have expired since registration
  const leafChainToken = session.chain[session.chain.length - 1]!
  if (new Date(leafChainToken.expiresAt) < new Date()) {
    throw new AmapError(
      AmapErrorCode.TOKEN_EXPIRED,
      `Session mandate for "${ctx.sessionId}" expired at ${leafChainToken.expiresAt}. ` +
        'Call amap_register_session again with a fresh mandate.',
    )
  }

  // Check that the cached verified mandate covers this specific tool
  const leafToken = session.verified.chain[session.verified.chain.length - 1]!.token
  const requiredPermission = `tool:${ctx.toolName}`
  if (!leafToken.permissions.includes(requiredPermission)) {
    throw new AmapError(
      AmapErrorCode.PERMISSION_INFLATION,
      `Mandate does not grant permission "${requiredPermission}" for tool "${ctx.toolName}"`,
    )
  }

  applyPolicyCheck(ctx.toolName, session.verified.effectiveConstraints)

  // Check parameterLocks — every locked parameter must match exactly
  const { parameterLocks } = session.verified.effectiveConstraints
  if (parameterLocks !== undefined) {
    for (const [key, lockedValue] of Object.entries(parameterLocks)) {
      if (input[key] !== lockedValue) {
        throw new AmapError(
          AmapErrorCode.PARAMETER_LOCK_VIOLATION,
          `Parameter "${key}" must be "${String(lockedValue)}" (locked by mandate), got "${String(input[key])}"`,
        )
      }
    }
  }

  return input
}

/**
 * Evaluates allow/deny policy constraints for a tool call.
 * Only runs when the mandate has allowedActions or deniedActions set.
 * Skipped on unconstrained mandates — evaluatePolicy() returns IMPLICIT_DENY when
 * allowedActions is undefined, which would incorrectly block everything.
 */
function applyPolicyCheck(toolName: string, effectiveConstraints: { allowedActions?: string[]; deniedActions?: string[] }): void {
  const { allowedActions, deniedActions } = effectiveConstraints
  if (allowedActions === undefined && deniedActions === undefined) return

  const decision = evaluatePolicy(toolName, effectiveConstraints)

  if (decision.decision === 'EXPLICIT_DENY') {
    throw new AmapError(
      AmapErrorCode.EXPLICIT_DENY,
      `Tool "${toolName}" is explicitly denied by mandate policy (rule: "${decision.matchedRule}")`,
    )
  }

  // IMPLICIT_DENY only blocks when allowedActions is set — means the tool is not on the allowlist.
  // Without allowedActions, deniedActions alone is a blocklist; unblocked tools pass through.
  if (decision.decision === 'IMPLICIT_DENY' && allowedActions !== undefined) {
    throw new AmapError(
      AmapErrorCode.EXPLICIT_DENY,
      `Tool "${toolName}" is not in mandate's allowedActions`,
    )
  }
}
