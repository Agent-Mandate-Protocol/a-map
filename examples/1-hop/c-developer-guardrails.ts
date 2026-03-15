/**
 * Scenario C — Developer Guardrails (Database Migration Agent)
 *
 * Alice gives a DevOps agent full autonomy to run tonight's database
 * schema migrations. It uses AmapPresets.Developer: everything allowed,
 * but hard stops on operations that can't be undone.
 *
 * The migration runs ALTER TABLE fine. Then it hits a foreign key error
 * and the LLM decides to DROP TABLE to clean up and retry. Blocked.
 * It then tries to force-push a revert commit. Also blocked.
 *
 * Key concept: You can give an agent "God Mode" for productivity while
 *              keeping physical stops on the operations that can't be undone.
 *              The agent's mistake becomes a log entry, not a production outage.
 *
 * Run: npx tsx examples/1-hop/c-developer-guardrails.ts
 */

import { amap, AmapPresets } from '../../sdks/typescript/core/src/index.js'
import { header, alice, agent, llm, ok, blocked, DIM, RESET, makeIdentities, tryRequest } from './_helpers.js'

export async function run() {
  header('SCENARIO C  —  Developer Guardrails (Database Migration Agent)')

  const { aliceKeys, agentKeys, aliceDid, agentDid, keyResolver } = makeIdentities()

  console.log()
  alice('"Run the pending schema migrations for tonight\'s release."')
  alice('Signs mandate with AmapPresets.Developer')
  alice('           → allowedActions: ["*"]  (full autonomy)')
  alice('           → deniedActions:  ["DROP TABLE", "DROP DATABASE", "git push --force", ...]')
  console.log()

  const mandate = await amap.issue({
    principal: aliceDid,
    delegate: agentDid,
    permissions: ['db:exec', 'shell:exec'],
    constraints: { ...AmapPresets.Developer },
    expiresIn: '2h',
    privateKey: aliceKeys.privateKey,
  })

  // Migration runs fine
  llm('Checking pending migrations...')
  llm('Running: 0042_add_user_prefs.sql')
  agent('db:exec("ALTER TABLE users ADD COLUMN preferences JSONB DEFAULT \'{}\'")')
  console.log()

  await tryRequest({
    mandate,
    agentPrivateKey: agentKeys.privateKey,
    keyResolver,
    method: 'POST',
    path: '/db/exec',
    expectedPermission: 'db:exec',
    requestedAction: 'ALTER TABLE users ADD COLUMN preferences JSONB',
  })
  ok('Schema migration runs. ALTER TABLE is safe — not in the deny list.')

  console.log()

  // Migration fails, LLM decides to DROP TABLE to retry
  llm('Migration 0043 failed: foreign key constraint on users_sessions.')
  llm('Decision → "Drop the sessions table and recreate with correct schema."')
  agent('db:exec("DROP TABLE users_sessions")')
  console.log()

  try {
    await tryRequest({
      mandate,
      agentPrivateKey: agentKeys.privateKey,
      keyResolver,
      method: 'POST',
      path: '/db/exec',
      expectedPermission: 'db:exec',
      requestedAction: 'DROP TABLE users_sessions',
    })
  } catch (e: unknown) {
    const err = e as { code: string }
    blocked(err.code, '"DROP TABLE" is in the deny list. Destructive schema change blocked.')
  }

  console.log()

  // LLM tries force push to revert
  llm('Decision → "Force-push a revert commit to undo the failed migration."')
  agent('shell:exec("git push --force origin main")')
  console.log()

  try {
    await tryRequest({
      mandate,
      agentPrivateKey: agentKeys.privateKey,
      keyResolver,
      method: 'POST',
      path: '/shell/exec',
      expectedPermission: 'shell:exec',
      requestedAction: 'git push --force origin main',
    })
  } catch (e: unknown) {
    const err = e as { code: string }
    blocked(err.code, '"git push --force" is in the deny list. Irreversible git operation blocked.')
  }

  console.log()
  console.log(`  ${DIM}Full autonomy for routine operations. Hard stops for production disasters.${RESET}`)
  console.log()
}

if (import.meta.url === `file://${process.argv[1]}`) {
  run().catch(console.error)
}
