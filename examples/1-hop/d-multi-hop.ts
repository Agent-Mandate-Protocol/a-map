/**
 * Scenario D — The Multi-Hop Chain (Research Pipeline)
 *
 * Alice hires an Orchestrator agent to research competitor pricing and write
 * the results to the CRM. The Orchestrator spins up a specialised ResearchBot
 * sub-agent to handle the web scraping — but only gives it web:read access,
 * keeping crm:write for itself.
 *
 * This demo shows the two invariants that JWT and OAuth cannot enforce:
 *
 * 1. PERMISSION NARROWING: ResearchBot tries to write to the CRM directly.
 *    It was never delegated that permission. A-MAP rejects it — the signed
 *    chain proves exactly what each hop was granted.
 *
 * 2. CONSTRAINT PROPAGATION: The Orchestrator tries to issue ResearchBot a
 *    token with a higher spend limit than Alice authorised. A-MAP rejects it
 *    at delegation time — constraints can only narrow, never relax.
 *
 * Run: npx tsx examples/1-hop/d-multi-hop.ts
 */

import { amap } from '../../sdks/typescript/core/src/index.js'
import { header, alice, agent, llm, ok, blocked, DIM, RESET, CYAN, YELLOW, PURPLE, BOLD, makeThreeIdentities, tryRequest } from './_helpers.js'

const orch     = (s: string) => console.log(`  ${CYAN}[Orchestrator]${RESET} ${s}`)
const research = (s: string) => console.log(`  ${YELLOW}[ResearchBot] ${RESET}${s}`)
const orchLlm  = (s: string) => console.log(`  ${PURPLE}[LLM ◉]${RESET} ${DIM}(Orchestrator) ${s}${RESET}`)
const resLlm   = (s: string) => console.log(`  ${PURPLE}[LLM ◉]${RESET} ${DIM}(ResearchBot)  ${s}${RESET}`)

export async function run() {
  header('SCENARIO D  —  The Multi-Hop Chain (Research Pipeline)')

  const {
    aliceKeys, agentKeys: orchKeys, subAgentKeys: researchKeys,
    aliceDid, agentDid: orchDid, subAgentDid: researchDid,
    keyResolver,
  } = makeThreeIdentities('orchestrator', 'research-bot')

  console.log()
  alice('"Research competitor pricing online and update our CRM with the findings."')
  alice(`Issues mandate → ${BOLD}Orchestrator${RESET}: permissions = ["web:read", "crm:write"]`)
  alice('                               constraints = { maxSpend: $10 }')
  console.log()

  const rootMandate = await amap.issue({
    principal: aliceDid,
    delegate: orchDid,
    permissions: ['web:read', 'crm:write'],
    constraints: { maxSpend: 10 },
    expiresIn: '1h',
    privateKey: aliceKeys.privateKey,
  })

  orchLlm('Spinning up ResearchBot for web scraping sub-task...')
  orch(`Delegates → ${BOLD}ResearchBot${RESET}: permissions = ["web:read"]  (crm:write NOT passed)`)
  orch('                          constraints = { maxSpend: $5 }  (tightened from $10)')
  console.log()

  const researchMandate = await amap.delegate({
    parentToken: rootMandate,
    parentChain: [rootMandate],
    delegate: researchDid,
    permissions: ['web:read'],           // narrowed — crm:write deliberately withheld
    constraints: { maxSpend: 5 },        // tightened — Orchestrator limits sub-agent budget
    expiresIn: '30m',
    privateKey: orchKeys.privateKey,
  })

  // ── Step 1: ResearchBot does its job ─────────────────────────────────────────

  resLlm('Scraping competitor pricing pages...')
  research('Calling web:read("https://competitor-a.com/pricing")')
  console.log()

  await tryRequest({
    mandateChain: [rootMandate, researchMandate],
    agentPrivateKey: researchKeys.privateKey,
    keyResolver,
    method: 'GET',
    path: '/web/read',
    expectedPermission: 'web:read',
  })
  ok('"web:read" is in ResearchBot\'s mandate. Research proceeds normally.')

  console.log()

  // ── Step 2: ResearchBot tries to write to CRM directly ───────────────────────

  resLlm('Research complete. Writing findings directly to CRM to save a round-trip.')
  research('Calling crm:write({ competitor: "Acme Inc", price: "$99/mo" })')
  console.log()

  try {
    await tryRequest({
      mandateChain: [rootMandate, researchMandate],
      agentPrivateKey: researchKeys.privateKey,
      keyResolver,
      method: 'POST',
      path: '/crm/write',
      expectedPermission: 'crm:write',
    })
  } catch (e: unknown) {
    const err = e as { code: string }
    blocked(
      err.code,
      '"crm:write" was granted to Orchestrator but NOT delegated to ResearchBot.',
    )
    console.log(`          ${DIM}The mandate chain proves it. The sub-agent cannot claim what it was never given.${RESET}`)
  }

  console.log()

  // ── Step 3: Orchestrator tries to inflate ResearchBot's spend limit ──────────

  orchLlm('ResearchBot needs more sources. Trying to raise its spend limit to $15.')
  orch('Attempting to re-delegate with maxSpend: $15 ...')
  console.log()

  try {
    await amap.delegate({
      parentToken: rootMandate,
      parentChain: [rootMandate],
      delegate: researchDid,
      permissions: ['web:read'],
      constraints: { maxSpend: 15 },    // tries to exceed Alice's $10 cap
      expiresIn: '30m',
      privateKey: orchKeys.privateKey,
    })
  } catch (e: unknown) {
    const err = e as { code: string }
    blocked(
      err.code,
      'Alice capped maxSpend at $10. Orchestrator cannot grant $15 to a sub-agent.',
    )
    console.log(`          ${DIM}Constraints can only narrow across the chain, never relax.${RESET}`)
  }

  console.log()
  console.log(`  ${DIM}Three hops. Two agents. One human in control.${RESET}`)
  console.log(`  ${DIM}JWT and OAuth have no answer for this. A-MAP does.${RESET}`)
  console.log()
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run().catch(console.error)
}
