/**
 * A-MAP MCP Server Demo
 *
 * A real MCP server you can explore interactively with MCP Inspector.
 * Shows how A-MAP mandate authorization works — cryptographic enforcement,
 * not just "please don't".
 *
 * Run:
 *   npx @modelcontextprotocol/inspector npx tsx examples/mcp-server/server.ts
 *
 * Try this flow in the Inspector:
 *   1. Call amap_issue  → get a mandate_token (opaque string)
 *   2. Call post_message  with that mandate_token → ✓ succeeds
 *   3. Call list_channels with the same token    → ✗ PERMISSION_INFLATION
 *   4. Call post_message  without a token        → ✗ BROKEN_CHAIN
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import {
  amap,
  LocalKeyResolver,
  InMemoryNonceStore,
  AmapError,
  AmapErrorCode,
} from '../../sdks/typescript/core/src/index.js'
import type { DelegationToken } from '../../sdks/typescript/core/src/index.js'

// ─── Demo identities ──────────────────────────────────────────────────────────
//
// Alice  = the human principal who issues mandates
// Agent  = the AI assistant acting on Alice's behalf
//
// Keys are generated fresh on each server start — no config needed.
// In production: Alice's key lives in her CLI/vault, agent key in the runtime.

const aliceKeys = amap.keygen()
const agentKeys = amap.keygen()

const aliceDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: aliceKeys.publicKey })
const agentDid = amap.computeDID({ type: 'agent', name: 'assistant', version: '1.0', publicKey: agentKeys.publicKey })

const keyResolver = new LocalKeyResolver(new Map([
  [aliceDid, aliceKeys.publicKey],
  [agentDid, agentKeys.publicKey],
]))

// Production: replace with Redis or Cloudflare KV for multi-instance deployments.
const nonceStore = new InMemoryNonceStore()

// ─── mandate_token ────────────────────────────────────────────────────────────
//
// We encode the DelegationToken as a base64url string so the user can
// copy-paste a single opaque value between tool calls in MCP Inspector —
// no need to manually construct X-AMAP-* headers.
//
// Internally, the server holds the agent private key and signs each request.

function encodeToken(token: DelegationToken): string {
  return Buffer.from(JSON.stringify(token)).toString('base64url')
}

function decodeToken(raw: string): DelegationToken {
  try {
    return JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')) as DelegationToken
  } catch {
    throw new AmapError(AmapErrorCode.BROKEN_CHAIN, 'Invalid mandate_token format.')
  }
}

// ─── Authorization helper ─────────────────────────────────────────────────────
//
// Takes a mandate_token string, signs a fresh request on behalf of the demo
// agent, and calls verifyRequest(). Throws AmapError on any failure.

async function authorize(mandateToken: string | undefined, toolName: string) {
  if (!mandateToken) {
    throw new AmapError(
      AmapErrorCode.BROKEN_CHAIN,
      `Tool "${toolName}" requires A-MAP authorization. Call amap_issue first to get a mandate_token.`,
    )
  }

  const token = decodeToken(mandateToken)

  const headers = amap.signRequest({
    mandateChain: [token],
    method: 'POST',
    path: `/mcp/${toolName}`,
    privateKey: agentKeys.privateKey,
  })

  return amap.verifyRequest({
    headers,
    method: 'POST',
    path: `/mcp/${toolName}`,
    expectedPermission: `tool:${toolName}`,
    keyResolver,
    nonceStore,
  })
}

function errorText(err: unknown): string {
  if (err instanceof AmapError) return `[${err.code}] ${err.message}`
  return err instanceof Error ? err.message : String(err)
}

// ─── MCP Server ───────────────────────────────────────────────────────────────

const server = new McpServer({ name: 'amap-demo', version: '1.0.0' })

// ── Tool 1: amap_issue ────────────────────────────────────────────────────────
//
// Alice signs a mandate granting the agent the requested permissions.
// Returns a mandate_token — an opaque string the user passes to other tools.

server.tool(
  'amap_issue',
  'Issue a signed A-MAP mandate. Returns a mandate_token to pass to other tools. Start here.',
  {
    permissions: z
      .array(z.string())
      .default(['tool:post_message'])
      .describe('Permissions to grant. Try "tool:post_message" or "tool:list_channels".'),
    reason: z
      .string()
      .optional()
      .describe('Optional: why does the agent need these permissions?'),
  },
  async ({ permissions, reason }) => {
    const token = await amap.issue({
      principal:  aliceDid,
      delegate:   agentDid,
      permissions,
      expiresIn:  '1h',
      privateKey: aliceKeys.privateKey,
    })

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          mandate_token: encodeToken(token),
          issued: {
            principal:   aliceDid,
            delegate:    agentDid,
            permissions,
            expiresAt:   token.expiresAt,
            ...(reason ? { reason } : {}),
          },
          next: 'Pass mandate_token to post_message or list_channels.',
        }, null, 2),
      }],
    }
  },
)

// ── Tool 2: post_message ──────────────────────────────────────────────────────
//
// Requires tool:post_message permission.
// Omit mandate_token → BROKEN_CHAIN
// Use a list_channels mandate → PERMISSION_INFLATION

server.tool(
  'post_message',
  'Post a message to the team channel. Requires tool:post_message permission. Pass mandate_token from amap_issue.',
  {
    message:       z.string().describe('The message to post'),
    mandate_token: z.string().optional().describe('Token from amap_issue. Omit to see BROKEN_CHAIN.'),
  },
  async ({ message, mandate_token }) => {
    try {
      const mandate = await authorize(mandate_token, 'post_message')
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            posted:       true,
            messageId:    `msg-${Date.now()}`,
            message,
            channel:      '#general',
            authorizedBy: mandate.principal,
          }, null, 2),
        }],
      }
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: errorText(err) }] }
    }
  },
)

// ── Tool 3: list_channels ─────────────────────────────────────────────────────
//
// Requires tool:list_channels permission.
// Use a post_message mandate → PERMISSION_INFLATION

server.tool(
  'list_channels',
  'List available channels. Requires tool:list_channels permission. Use a post_message mandate to see PERMISSION_INFLATION.',
  {
    mandate_token: z.string().optional().describe('Token from amap_issue. Omit to see BROKEN_CHAIN.'),
  },
  async ({ mandate_token }) => {
    try {
      const mandate = await authorize(mandate_token, 'list_channels')
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            channels: [
              { id: 'C001', name: 'general',     memberCount: 42 },
              { id: 'C002', name: 'engineering',  memberCount: 18 },
              { id: 'C003', name: 'exec-private', memberCount: 4  },
            ],
            authorizedBy: mandate.principal,
          }, null, 2),
        }],
      }
    } catch (err) {
      return { isError: true, content: [{ type: 'text', text: errorText(err) }] }
    }
  },
)

// ─── Start ────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport()
await server.connect(transport)

process.stderr.write('\n  A-MAP Demo Server running. Connect via MCP Inspector.\n\n')
process.stderr.write('  Flow:\n')
process.stderr.write('    1. amap_issue    { permissions: ["tool:post_message"] }    → mandate_token\n')
process.stderr.write('    2. post_message  { message: "Hi", mandate_token: "..." }  → ✓ posted\n')
process.stderr.write('    3. list_channels { mandate_token: "..." }                  → ✗ PERMISSION_INFLATION\n')
process.stderr.write('    4. post_message  { message: "Hi" }                         → ✗ BROKEN_CHAIN\n\n')
