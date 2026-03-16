import type { DelegationToken } from '@agentmandateprotocol/core'

function formatExpiry(expiresAt: string): string {
  const expiry = new Date(expiresAt)
  const now = new Date()
  const isExpired = expiry < now
  const diffMs = Math.abs(expiry.getTime() - now.getTime())
  const diffMin = Math.floor(diffMs / 60_000)
  const diffHrs = Math.floor(diffMin / 60)
  const diffDays = Math.floor(diffHrs / 24)

  let relative: string
  if (isExpired) {
    if (diffDays > 0) relative = `expired ${diffDays}d ago`
    else if (diffHrs > 0) relative = `expired ${diffHrs}h ago`
    else relative = `expired ${diffMin}m ago`
  } else {
    if (diffDays > 0) relative = `expires in ${diffDays}d`
    else if (diffHrs > 0) relative = `expires in ${diffHrs}h`
    else relative = `expires in ${diffMin}m`
  }

  return `${expiresAt} (${relative})`
}

function formatConstraints(constraints: DelegationToken['constraints']): string {
  const parts: string[] = []
  if (constraints.maxSpend !== undefined) parts.push(`maxSpend: $${String(constraints.maxSpend)}`)
  if (constraints.maxCalls !== undefined) parts.push(`maxCalls: ${String(constraints.maxCalls)}`)
  if (constraints.readOnly === true) parts.push('readOnly: true')
  if (constraints.allowedDomains !== undefined) parts.push(`allowedDomains: [${constraints.allowedDomains.join(', ')}]`)
  if (constraints.allowedActions !== undefined) parts.push(`allowedActions: [${constraints.allowedActions.join(', ')}]`)
  if (constraints.parameterLocks !== undefined) {
    const locks = Object.entries(constraints.parameterLocks)
      .map(([k, v]) => `${k}=${String(v)}`)
      .join(', ')
    parts.push(`parameterLocks: {${locks}}`)
  }
  if (constraints.rateLimit !== undefined) {
    parts.push(`rateLimit: ${String(constraints.rateLimit.count)} per ${String(constraints.rateLimit.windowSeconds)}s`)
  }
  return parts.length > 0 ? parts.join(', ') : '(none)'
}

export function runVerify(chainBase64url: string): void {
  let chain: DelegationToken[]

  try {
    const decoded = Buffer.from(chainBase64url, 'base64url').toString('utf8')
    chain = JSON.parse(decoded) as DelegationToken[]
  } catch {
    console.error('Error: Could not decode mandate chain. Ensure it is a valid base64url-encoded JSON array.')
    process.exitCode = 1
    return
  }

  if (!Array.isArray(chain) || chain.length === 0) {
    console.error('Error: Mandate chain must be a non-empty JSON array.')
    process.exitCode = 1
    return
  }

  console.log('')
  console.log('=== Mandate Chain Decode ===')
  console.log(`Chain length: ${chain.length} hop${chain.length === 1 ? '' : 's'}`)
  console.log('')
  console.log('Note: This command decodes the chain only — no cryptographic verification.')
  console.log('      Use amap.verify() in code for full signature + constraint verification.')
  console.log('')

  let anyExpired = false

  chain.forEach((token, idx) => {
    const isLast = idx === chain.length - 1
    const hopLabel = idx === 0 ? 'Root (human-issued)' : `Hop ${idx}`
    const expiry = new Date(token.expiresAt)
    const expired = expiry < new Date()
    if (expired) anyExpired = true

    console.log(`--- Token ${idx + 1} of ${chain.length}: ${hopLabel} ---`)
    console.log(`  Token ID:    ${token.tokenId}`)
    console.log(`  Issuer:      ${token.issuer}`)
    console.log(`  Delegate:    ${token.delegate}`)
    console.log(`  Principal:   ${token.principal}`)
    console.log(`  Permissions: ${token.permissions.join(', ')}`)
    console.log(`  Constraints: ${formatConstraints(token.constraints)}`)
    console.log(`  Issued at:   ${token.issuedAt}`)
    console.log(`  Expires at:  ${formatExpiry(token.expiresAt)}`)
    console.log(`  Status:      ${expired ? 'EXPIRED' : 'valid'}`)
    if (token.parentTokenHash !== null) {
      console.log(`  Parent hash: ${token.parentTokenHash.slice(0, 16)}...`)
    } else {
      console.log('  Parent hash: (none — root token)')
    }
    if (token.intentHash !== undefined) {
      console.log(`  Intent hash: ${token.intentHash}`)
    }
    if (isLast) {
      console.log('  (leaf — this agent presents this chain)')
    }
    console.log('')
  })

  if (anyExpired) {
    console.log('WARNING: One or more tokens in this chain are expired.')
  } else {
    console.log('All tokens in the chain are within their expiry window.')
  }
  console.log('')
}
