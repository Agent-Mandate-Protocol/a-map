/**
 * A-MAP Agent-to-Agent (A2A) Demo — Multi-hop delegation with budget constraints
 *
 * Alice hires an orchestrator agent to run a competitive research project.
 * The orchestrator sub-delegates to a web crawler worker with a narrowed budget.
 * The worker cannot inflate its own spend limit — the chain enforces it.
 *
 * Delegation chain:
 *   Alice →(web:read + crm:write, maxSpend: $100)→ Orchestrator
 *         →(web:read only,        maxSpend: $10) → Worker
 *
 * Run: npx tsx examples/a2a/demo.ts
 */

import { amap } from '../../sdks/typescript/core/src/index.js'
import { humanDid, humanKeys, orchestratorDid } from './shared.js'
import { ResearchOrchestrator } from './orchestrator.js'
import { WebCrawlerWorker } from './worker.js'

async function main() {
  console.log('\n--- A-MAP MULTI-AGENT TRUST DEMO ---\n')

  // Step 1: Alice issues a root mandate to the orchestrator.
  // The orchestrator is authorised up to $100 with two capabilities.
  const aliceMandate = await amap.issue({
    principal: humanDid,
    delegate: orchestratorDid,
    permissions: ['web:read', 'crm:write'],
    constraints: { maxSpend: 100 },
    expiresIn: '1h',
    privateKey: humanKeys.privateKey,
  })

  const orchestrator = new ResearchOrchestrator()
  await orchestrator.startProject([aliceMandate])

  // Step 2: Orchestrator delegates to the worker with narrowed scope.
  // - Permissions narrowed: worker gets only web:read, not crm:write
  // - Budget narrowed:      worker gets $10, not $100
  // These constraints are cryptographically enforced in the chain.
  const workerMandate = await orchestrator.hireWorker()
  const worker = new WebCrawlerWorker()

  // Scenario 1: Honest worker spends within its limit
  // $5 spend against a $10 mandate — approved
  console.log('\n--- Scenario 1: Honest worker (spend: $5 / limit: $10) ---')
  await worker.crawlWebsite(workerMandate, 5)

  // Scenario 2: Worker tries to spend more than its mandate allows
  // The worker has a $10 mandate. It declares $15 spend.
  // effectiveConstraints.maxSpend = min(100, 10) = 10 — most restrictive wins.
  // $15 > $10 → rejected. The worker cannot use the orchestrator's full $100 budget.
  console.log('\n--- Scenario 2: Greedy worker (spend: $15 / limit: $10) ---')
  console.log('[Worker]   Attempting to use the orchestrator\'s $100 budget...')
  await worker.crawlWebsite(workerMandate, 15)

  console.log('\n--- Summary ---')
  console.log('The worker received a cryptographically bounded sub-mandate.')
  console.log('It could not spend beyond $10 — even though the orchestrator had $100.')
  console.log('The constraint merged across the chain: min(100, 10) = 10. Cannot be inflated.')
  console.log('See examples/1-hop/a-permission-blocking.ts for the permission narrowing equivalent.')
  console.log()
}

main().catch(console.error)
