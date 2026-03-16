import { createInterface } from 'node:readline/promises'
import { stdin as input, stdout as output } from 'node:process'
import { createPrivateKey, createPublicKey } from 'node:crypto'
import { amap } from '@agentmandateprotocol/core'
import type { Constraints } from '@agentmandateprotocol/core'

function derivePublicKey(privateKeyBase64url: string): string {
  const privateKeyObj = createPrivateKey({
    key: Buffer.from(privateKeyBase64url, 'base64url'),
    format: 'der',
    type: 'pkcs8',
  })
  const publicKeyObj = createPublicKey(privateKeyObj)
  return (publicKeyObj.export({ type: 'spki', format: 'der' }) as Buffer).toString('base64url')
}

async function readHidden(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    // Non-TTY (e.g. piped input): read a line normally
    const rl = createInterface({ input, output, terminal: false })
    process.stdout.write(prompt)
    const answer = await new Promise<string>((resolve) => {
      rl.once('line', (line) => {
        rl.close()
        resolve(line)
      })
    })
    return answer
  }

  // TTY: hide input using raw mode
  return new Promise((resolve, reject) => {
    process.stdout.write(prompt)
    process.stdin.setRawMode(true)
    process.stdin.resume()
    process.stdin.setEncoding('utf8')

    let value = ''

    const onData = (ch: string) => {
      if (ch === '\r' || ch === '\n') {
        process.stdin.setRawMode(false)
        process.stdin.pause()
        process.stdin.removeListener('data', onData)
        process.stdin.removeListener('error', onError)
        process.stdout.write('\n')
        resolve(value)
      } else if (ch === '\u0003') {
        // Ctrl-C
        process.stdin.setRawMode(false)
        process.stdin.pause()
        process.stdin.removeListener('data', onData)
        process.stdin.removeListener('error', onError)
        process.stdout.write('\n')
        reject(new Error('Interrupted'))
      } else if (ch === '\u007f' || ch === '\b') {
        // Backspace
        value = value.slice(0, -1)
      } else {
        value += ch
      }
    }

    const onError = (err: Error) => {
      reject(err)
    }

    process.stdin.on('data', onData)
    process.stdin.on('error', onError)
  })
}

export async function runIssue(): Promise<void> {
  const rl = createInterface({ input, output })

  try {
    console.log('')
    console.log('=== A-MAP Issue Mandate ===')
    console.log('Answer the questions below to create a signed delegation token.')
    console.log('')

    const delegateDid = (await rl.question('Agent DID (delegate): ')).trim()
    if (!delegateDid) {
      console.error('Error: Agent DID is required.')
      process.exitCode = 1
      return
    }

    const permissionsRaw = (await rl.question('Permissions (comma-separated, e.g. email:read,github:push): ')).trim()
    if (!permissionsRaw) {
      console.error('Error: At least one permission is required.')
      process.exitCode = 1
      return
    }
    const permissions = permissionsRaw.split(',').map((p) => p.trim()).filter(Boolean)

    const constraints: Partial<Constraints> = {}

    const maxSpendRaw = (await rl.question('Max spend limit in USD (blank to skip): ')).trim()
    if (maxSpendRaw !== '') {
      const n = Number(maxSpendRaw)
      if (isNaN(n) || n < 0) {
        console.error('Error: Max spend must be a non-negative number.')
        process.exitCode = 1
        return
      }
      constraints.maxSpend = n
    }

    const maxCallsRaw = (await rl.question('Max calls (blank to skip): ')).trim()
    if (maxCallsRaw !== '') {
      const n = Number(maxCallsRaw)
      if (isNaN(n) || n < 0 || !Number.isInteger(n)) {
        console.error('Error: Max calls must be a non-negative integer.')
        process.exitCode = 1
        return
      }
      constraints.maxCalls = n
    }

    const paramLockRaw = (await rl.question('Lock a parameter? Format: key=value (blank to skip): ')).trim()
    if (paramLockRaw !== '') {
      const eqIdx = paramLockRaw.indexOf('=')
      if (eqIdx < 1) {
        console.error('Error: Parameter lock must be in key=value format.')
        process.exitCode = 1
        return
      }
      const lockKey = paramLockRaw.slice(0, eqIdx).trim()
      const lockVal = paramLockRaw.slice(eqIdx + 1).trim()
      constraints.parameterLocks = { [lockKey]: lockVal }
    }

    const ttlChoices = ['15m', '1h', '4h', '24h']
    const ttlRaw = (await rl.question('Expires in (15m / 1h / 4h / 24h) [1h]: ')).trim() || '1h'
    if (!ttlChoices.includes(ttlRaw)) {
      console.error(`Error: Expiry must be one of: ${ttlChoices.join(', ')}`)
      process.exitCode = 1
      return
    }

    const userName = (await rl.question('Your name (for DID computation, e.g. alice): ')).trim()
    if (!userName) {
      console.error('Error: Your name is required.')
      process.exitCode = 1
      return
    }

    // Close readline before reading hidden input to avoid conflicts
    rl.close()

    const privateKeyBase64url = (await readHidden('Your private key (base64url): ')).trim()
    if (!privateKeyBase64url) {
      console.error('Error: Private key is required.')
      process.exitCode = 1
      return
    }

    // Derive public key and issuer DID
    let publicKey: string
    try {
      publicKey = derivePublicKey(privateKeyBase64url)
    } catch {
      console.error('Error: Could not derive public key from private key. Ensure it is a valid base64url-encoded Ed25519 PKCS8 private key.')
      process.exitCode = 1
      return
    }

    const issuerDid = amap.computeDID({ type: 'human', name: userName, publicKey })

    const hasConstraints = Object.keys(constraints).length > 0
    const token = await amap.issue({
      principal: issuerDid,
      delegate: delegateDid,
      permissions,
      ...(hasConstraints ? { constraints: constraints as Constraints } : {}),
      expiresIn: ttlRaw,
      privateKey: privateKeyBase64url,
    })

    const chain = [token]
    const chainBase64url = Buffer.from(JSON.stringify(chain)).toString('base64url')

    console.log('')
    console.log('=== Mandate Issued Successfully ===')
    console.log('')
    console.log('Issuer DID:')
    console.log('  ' + issuerDid)
    console.log('')
    console.log('X-AMAP-Mandate header value (base64url chain):')
    console.log('  ' + chainBase64url)
    console.log('')
    console.log('Full token JSON:')
    console.log(JSON.stringify(token, null, 2))
    console.log('')
  } catch (err) {
    if (err instanceof Error && err.message === 'Interrupted') {
      console.error('\nInterrupted.')
      process.exitCode = 1
    } else {
      throw err
    }
  } finally {
    // rl may already be closed if we went through the hidden input path
    try { rl.close() } catch { /* already closed */ }
  }
}
