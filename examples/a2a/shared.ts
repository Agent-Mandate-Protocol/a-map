/**
 * Shared identity setup for the A2A demo.
 *
 * Keys are generated fresh at startup — no hardcoded private keys in source.
 * DIDs are self-certifying: derived deterministically from each public key.
 * In production: load keypairs from a secrets manager, HSM, or secure enclave.
 */
import { amap } from '../../sdks/typescript/core/src/index.js'
export type { DelegationToken } from '../../sdks/typescript/core/src/index.js'

// --- Keypairs (generated fresh on every run) ---
export const humanKeys        = amap.keygen()
export const orchestratorKeys = amap.keygen()
export const workerKeys       = amap.keygen()

// --- Self-certifying DIDs (fingerprint derived from public key) ---
export const humanDid = amap.computeDID({
  type: 'human',
  name: 'alice',
  publicKey: humanKeys.publicKey,
})

export const orchestratorDid = amap.computeDID({
  type: 'agent',
  name: 'orchestrator',
  version: '1.0',
  publicKey: orchestratorKeys.publicKey,
})

export const workerDid = amap.computeDID({
  type: 'agent',
  name: 'web-crawler',
  version: '1.0',
  publicKey: workerKeys.publicKey,
})
