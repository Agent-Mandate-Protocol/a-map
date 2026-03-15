/**
 * A-MAP Hero Demo — all 4 scenarios in sequence.
 *
 * Run: npx tsx examples/1-hop/demo.ts
 *
 * To run a single scenario:
 *   npx tsx examples/1-hop/a-permission-blocking.ts
 *   npx tsx examples/1-hop/b-prompt-injection.ts
 *   npx tsx examples/1-hop/c-developer-guardrails.ts
 *   npx tsx examples/1-hop/d-multi-hop.ts
 */

import { BOLD, DIM, RESET, line } from './_helpers.js'
import { run as runA } from './a-permission-blocking.js'
import { run as runB } from './b-prompt-injection.js'
import { run as runC } from './c-developer-guardrails.js'
import { run as runD } from './d-multi-hop.js'

async function main() {
  console.log('\n' + BOLD + '  A-MAP Hero Demo — Cryptographic Agent Authorization' + RESET)
  console.log(DIM + '  Fully offline · no servers · no LLM calls\n' + RESET)

  await runA()
  await runB()
  await runC()
  await runD()

  line()
  console.log()
  console.log(BOLD + '  All 4 scenarios complete.' + RESET)
  console.log(`  ${DIM}Zero network calls. Zero LLM calls. Pure cryptographic enforcement.${RESET}`)
  console.log()
}

main().catch(console.error)
