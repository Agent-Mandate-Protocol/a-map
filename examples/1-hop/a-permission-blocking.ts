/**
 * Scenario A — The Strict Boundary (GitHub Code Auditor)
 *
 * Alice hires an AI code reviewer to audit her company's API repo for
 * security vulnerabilities. The agent is given read access to scan the code.
 *
 * The LLM finds a real SQL injection bug and decides — correctly — that it
 * should patch it immediately. It tries to push the fix. A-MAP blocks it.
 *
 * Key concept: permissions = ["github:read"] means READ ONLY.
 *              The agent's intent to "fix the bug" is irrelevant.
 *              This is CANNOT, not "please don't".
 *
 * Run: npx tsx examples/1-hop/a-permission-blocking.ts
 */

import { amap } from '../../sdks/typescript/core/src/index.js'
import { header, alice, agent, llm, blocked, DIM, RESET, makeIdentities, tryRequest } from './_helpers.js'

export async function run() {
  header('SCENARIO A  —  The Strict Boundary (GitHub Code Auditor)')

  const { aliceKeys, agentKeys, aliceDid, agentDid, keyResolver } = makeIdentities()

  console.log()
  alice('"Audit our API repo for security vulnerabilities and report what you find."')
  alice('Signs mandate: permissions = ["github:read"]')
  console.log()

  const mandate = await amap.issue({
    principal: aliceDid,
    delegate: agentDid,
    permissions: ['github:read'],
    expiresIn: '1h',
    privateKey: aliceKeys.privateKey,
  })

  llm('Cloning repository acme/api...')
  llm('Scanning 1,247 source files...')
  llm('Found: SQL injection vulnerability in src/auth/login.ts line 47')
  llm('Found: Hardcoded DB credentials in config/db.ts line 12')
  llm('Decision → "I should patch these immediately before they are exploited."')
  console.log()

  agent('Calling github:push(repo: "acme/api", branch: "main", file: "src/auth/login.ts")')
  console.log()

  try {
    await tryRequest({
      mandate,
      agentPrivateKey: agentKeys.privateKey,
      keyResolver,
      method: 'POST',
      path: '/github/push',
      expectedPermission: 'github:push',
    })
  } catch (e: unknown) {
    const err = e as { code: string }
    blocked(err.code, '"github:push" was not granted. Alice only authorized "github:read".')
  }

  console.log()
  console.log(`  ${DIM}The agent found a real bug and tried to do the right thing.${RESET}`)
  console.log(`  ${DIM}A-MAP stopped it anyway. Scope limits are not optional.${RESET}`)
  console.log()
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run().catch(console.error)
}
