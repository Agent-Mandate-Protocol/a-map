import { amap, LocalKeyResolver, InMemoryNonceStore } from '../../sdks/typescript/core/src/index.js'
import type { DelegationToken } from '../../sdks/typescript/core/src/index.js'
import { humanDid, humanKeys, orchestratorDid, orchestratorKeys, workerDid, workerKeys } from './shared.js'

/**
 * Simulates two parties in one file for demo clarity.
 * In production these run on separate machines:
 *   Agent side  — the worker process that signs outgoing requests
 *   Service side — the crawl API that verifies before executing
 */
export class WebCrawlerWorker {
  // Service side: knows the public keys of every party in the chain.
  // In production: populated from a hosted registry or pre-shared key list.
  private readonly keyResolver = new LocalKeyResolver(new Map([
    [humanDid,        humanKeys.publicKey],
    [orchestratorDid, orchestratorKeys.publicKey],
    [workerDid,       workerKeys.publicKey],
  ]))

  // Service side: tracks seen nonces to prevent request replay.
  // In production with multiple API instances: use Redis or Cloudflare KV.
  private readonly nonceStore = new InMemoryNonceStore()

  async crawlWebsite(mandate: DelegationToken[], spend: number): Promise<{ success: boolean; auditId?: string; error?: string }> {
    console.log(`[Worker]   Signing request to crawl competitor.com. Declared spend: $${spend}`)

    // --- Agent side: sign the outgoing request ---
    // The worker signs with its own private key + attaches the full mandate chain.
    // This proves: (1) this specific agent is making this request right now,
    // (2) the nonce prevents replay even if the headers are intercepted.
    const headers = amap.signRequest({
      mandateChain: mandate,
      method: 'POST',
      path: '/crawl',
      body: JSON.stringify({ url: 'https://competitor.com' }),
      privateKey: workerKeys.privateKey,
    })

    // --- Service side: verify before executing ---
    // verifyRequest checks:
    //   ✓ Mandate chain valid (Alice → Orchestrator → Worker, all signatures correct)
    //   ✓ Request signature valid (signed by the worker's key)
    //   ✓ Nonce not seen before (replay prevention)
    //   ✓ Timestamp within ±5 minutes (stale request prevention)
    //   ✓ 'web:read' permission present at the leaf
    try {
      const result = await amap.verifyRequest({
        headers,
        method: 'POST',
        path: '/crawl',
        body: JSON.stringify({ url: 'https://competitor.com' }),
        expectedPermission: 'web:read',
        keyResolver: this.keyResolver,
        nonceStore: this.nonceStore,
      })

      // A-MAP returns the effective constraints — the most restrictive values
      // across the full chain. Here: min(100, 10) = 10.
      // The service is responsible for enforcing runtime values like spend.
      // (verifyRequest cannot enforce maxSpend because it doesn't know the
      //  actual spend amount until the request is processed.)
      const maxAllowed = result.effectiveConstraints.maxSpend ?? 0

      if (spend > maxAllowed) {
        console.log(`[Service]  ❌ REJECTED: $${spend} spend exceeds mandate limit of $${maxAllowed}`)
        return { success: false, error: `Spend $${spend} exceeds mandate limit $${maxAllowed}` }
      }

      console.log(`[Service]  ✅ APPROVED: $${spend} within $${maxAllowed} limit.`)
      console.log(`[Service]     Principal: ${result.principal}`)
      console.log(`[Service]     Audit ID:  ${result.auditId}`)
      return { success: true, auditId: result.auditId }

    } catch (err: unknown) {
      const e = err as { code?: string; message: string }
      console.log(`[Service]  ❌ REJECTED: ${e.code ?? 'ERROR'} — ${e.message}`)
      return { success: false, error: e.message }
    }
  }
}
