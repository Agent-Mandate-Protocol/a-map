#!/usr/bin/env node
import { runKeygen } from './commands/keygen.js'
import { runIssue } from './commands/issue.js'
import { runVerify } from './commands/verify.js'

const command = process.argv[2]

function showUsage(): void {
  console.log('')
  console.log('Usage: amap <command> [args]')
  console.log('')
  console.log('Commands:')
  console.log('  keygen <name> [version]   Generate an Ed25519 keypair and DID')
  console.log('  issue                     Interactive wizard to issue a root mandate')
  console.log('  verify <chain>            Decode and display a base64url mandate chain')
  console.log('')
  console.log('Examples:')
  console.log('  amap keygen alice')
  console.log('  amap issue')
  console.log('  amap verify <base64url-encoded-chain>')
  console.log('')
}

async function main(): Promise<void> {
  if (!command || command === '--help' || command === '-h') {
    showUsage()
    return
  }

  switch (command) {
    case 'keygen': {
      const name = process.argv[3]
      const version = process.argv[4]
      if (!name) {
        console.error('Error: keygen requires a name argument.')
        console.error('Usage: amap keygen <name> [version]')
        process.exitCode = 1
        return
      }
      await runKeygen(name, version)
      break
    }

    case 'issue': {
      await runIssue()
      break
    }

    case 'verify': {
      const chain = process.argv[3]
      if (!chain) {
        console.error('Error: verify requires a base64url-encoded mandate chain argument.')
        console.error('Usage: amap verify <chain>')
        process.exitCode = 1
        return
      }
      runVerify(chain)
      break
    }

    default: {
      console.error(`Error: Unknown command "${command}"`)
      showUsage()
      process.exitCode = 1
    }
  }
}

main().catch((err) => {
  console.error('Unexpected error:', err instanceof Error ? err.message : String(err))
  process.exitCode = 1
})
