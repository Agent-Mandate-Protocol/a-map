import { amap } from '@agentmandateprotocol/core'

export async function runKeygen(name: string, version = '1.0'): Promise<void> {
  const { publicKey, privateKey } = amap.keygen()
  const did = amap.computeDID({ type: 'human', name, publicKey })

  console.log('')
  console.log('=== A-MAP Keypair Generated ===')
  console.log('')
  console.log('DID:')
  console.log('  ' + did)
  console.log('')
  console.log('Public key (base64url):')
  console.log('  ' + publicKey)
  console.log('')
  console.log('Private key (base64url):')
  console.log('  ' + privateKey)
  console.log('')
  console.log('WARNING: Store your private key securely. Never share it.')
  console.log('WARNING: Anyone with your private key can issue mandates on your behalf.')
  console.log('')
}
