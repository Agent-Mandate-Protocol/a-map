/**
 * Shared output helpers and identity setup for 1-hop examples.
 */

import { amap, LocalKeyResolver, InMemoryNonceStore } from '../../sdks/typescript/core/src/index.js'
import type { DelegationToken } from '../../sdks/typescript/core/src/index.js'

// ─── ANSI colours ─────────────────────────────────────────────────────────────

export const RESET   = '\x1b[0m'
export const BOLD    = '\x1b[1m'
export const DIM     = '\x1b[2m'
export const GREEN   = '\x1b[32m'
export const RED     = '\x1b[31m'
export const CYAN    = '\x1b[36m'
export const YELLOW  = '\x1b[33m'
export const PURPLE  = '\x1b[35m'

// ─── Narrative output ──────────────────────────────────────────────────────────

export const line    = () => console.log(DIM + '─'.repeat(60) + RESET)
export const header  = (s: string) => { line(); console.log(BOLD + '  ' + s + RESET); line() }
export const alice   = (s: string) => console.log(`  ${CYAN}[Alice] ${RESET}${s}`)
export const agent   = (s: string) => console.log(`  ${YELLOW}[Agent] ${RESET}${s}`)
export const llm     = (s: string) => console.log(`  ${PURPLE}[LLM ◉]${RESET} ${DIM}${s}${RESET}`)
export const ok      = (s: string) => console.log(`  ${GREEN}[A-MAP] ✓ ALLOWED${RESET}  ${s}`)
export const blocked = (code: string, reason: string) => {
  console.log(`  ${RED}[A-MAP] ✗ BLOCKED${RESET}  ${BOLD}${code}${RESET}`)
  console.log(`          ${DIM}${reason}${RESET}`)
}

// ─── Identity factory ──────────────────────────────────────────────────────────

export function makeIdentities() {
  const aliceKeys = amap.keygen()
  const agentKeys = amap.keygen()

  const aliceDid = amap.computeDID({ type: 'human', name: 'alice', publicKey: aliceKeys.publicKey })
  const agentDid = amap.computeDID({ type: 'agent', name: 'assistant', version: '1.0', publicKey: agentKeys.publicKey })

  const keyResolver = new LocalKeyResolver(new Map([
    [aliceDid, aliceKeys.publicKey],
    [agentDid, agentKeys.publicKey],
  ]))

  return { aliceKeys, agentKeys, aliceDid, agentDid, keyResolver }
}

export function makeThreeIdentities(agentName: string, subAgentName: string) {
  const aliceKeys = amap.keygen()
  const agentKeys = amap.keygen()
  const subAgentKeys = amap.keygen()

  const aliceDid     = amap.computeDID({ type: 'human', name: 'alice', publicKey: aliceKeys.publicKey })
  const agentDid     = amap.computeDID({ type: 'agent', name: agentName, version: '1.0', publicKey: agentKeys.publicKey })
  const subAgentDid  = amap.computeDID({ type: 'agent', name: subAgentName, version: '1.0', publicKey: subAgentKeys.publicKey })

  const keyResolver = new LocalKeyResolver(new Map([
    [aliceDid,    aliceKeys.publicKey],
    [agentDid,    agentKeys.publicKey],
    [subAgentDid, subAgentKeys.publicKey],
  ]))

  return { aliceKeys, agentKeys, subAgentKeys, aliceDid, agentDid, subAgentDid, keyResolver }
}

// ─── Request helper ────────────────────────────────────────────────────────────

export async function tryRequest(opts: {
  mandate?: DelegationToken
  mandateChain?: DelegationToken[]
  agentPrivateKey: string
  keyResolver: LocalKeyResolver
  method: string
  path: string
  expectedPermission?: string
  requestParams?: Record<string, unknown>
  requestedAction?: string
}) {
  const chain = opts.mandateChain ?? [opts.mandate!]
  const headers = amap.signRequest({
    mandateChain: chain,
    method: opts.method,
    path: opts.path,
    privateKey: opts.agentPrivateKey,
  })
  return amap.verifyRequest({
    headers,
    method: opts.method,
    path: opts.path,
    nonceStore: new InMemoryNonceStore(),
    keyResolver: opts.keyResolver,
    ...(opts.expectedPermission !== undefined ? { expectedPermission: opts.expectedPermission } : {}),
    ...(opts.requestParams !== undefined      ? { requestParams: opts.requestParams }           : {}),
    ...(opts.requestedAction !== undefined    ? { requestedAction: opts.requestedAction }       : {}),
  })
}
