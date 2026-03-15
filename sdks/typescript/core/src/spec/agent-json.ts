import type { Constraints } from '../types/constraints.js'

/**
 * The /.well-known/agent.json manifest served by A-MAP-protected APIs.
 *
 * Agents fetch this endpoint before calling a service to discover:
 * - What permissions they need to request from the human
 * - What constraints the service enforces on mandates
 * - How to resolve the service's public key (registry or inline)
 *
 * JSON Schema: spec/agent-json.schema.json
 * Formal specification: https://agentmandateprotocol.dev/spec/agent-json/1.0
 */
export interface AgentJson {
  /** A-MAP protocol version. Currently: '1.0' */
  amap: '1.0'

  /** DID of this service in did:amap format */
  did: string

  /**
   * If true, all incoming requests must carry a valid X-AMAP-Mandate header.
   * Default: true
   */
  requiresDelegationChain?: boolean

  /**
   * Permission strings the agent must hold in its mandate chain.
   * Agents should request exactly these permissions from the human
   * before obtaining a mandate.
   *
   * @example ['email:read', 'email:send']
   */
  requiredPermissions?: string[]

  /**
   * Constraints this service enforces on incoming mandates.
   * Agents should ensure their mandate satisfies these before calling.
   */
  constraints?: Partial<Constraints>

  /**
   * URL of the A-MAP registry for DID resolution.
   * Used by agents that do not have the service's public key cached locally.
   */
  registryUrl?: string

  /**
   * base64url-encoded Ed25519 public key of this service.
   * When present, agents can verify signatures fully offline.
   */
  publicKey?: string

  /** Contact email or URL for security issues and abuse reports */
  contact?: string

  /** Human-readable service name. Displayed in consent UIs and audit logs. */
  name?: string

  /** Short description of what this service does. Displayed in consent UIs. */
  description?: string

  /** URL to A-MAP integration documentation for this service */
  docsUrl?: string

  /** Extension fields — tool providers may add custom fields */
  [key: string]: unknown
}

/**
 * Create a valid AgentJson manifest object.
 *
 * Automatically injects `amap: '1.0'` and defaults `requiresDelegationChain`
 * to `true`. All provided fields are passed through unchanged.
 *
 * @example Hono
 * ```ts
 * app.get('/.well-known/agent.json', (c) =>
 *   c.json(createAgentJson({
 *     did: myServiceDid,
 *     requiredPermissions: ['email:read'],
 *     constraints: { maxCalls: 100 },
 *     publicKey: myPublicKey,
 *   }))
 * )
 * ```
 *
 * @example Express
 * ```ts
 * app.get('/.well-known/agent.json', (req, res) =>
 *   res.json(createAgentJson({
 *     did: myServiceDid,
 *     requiredPermissions: ['github:push'],
 *   }))
 * )
 * ```
 *
 * @example Fetch / Cloudflare Workers
 * ```ts
 * if (url.pathname === '/.well-known/agent.json') {
 *   return Response.json(createAgentJson({ did: myServiceDid }))
 * }
 * ```
 */
export function createAgentJson(manifest: Omit<AgentJson, 'amap'>): AgentJson {
  return Object.assign(
    { amap: '1.0' as const, requiresDelegationChain: true },
    manifest,
  ) as AgentJson
}

/**
 * Fetch and parse an AgentJson manifest from a remote service.
 *
 * @param baseUrl - Base URL of the service (e.g. 'https://api.example.com')
 * @returns Parsed AgentJson manifest
 * @throws If the fetch fails or the response is not valid JSON
 *
 * @example
 * ```ts
 * const manifest = await fetchAgentJson('https://api.example.com')
 * console.log(manifest.requiredPermissions) // ['email:read']
 * ```
 */
export async function fetchAgentJson(baseUrl: string): Promise<AgentJson> {
  const url = baseUrl.replace(/\/$/, '') + '/.well-known/agent.json'
  const res = await fetch(url)
  if (!res.ok) {
    throw new Error(`Failed to fetch agent.json from ${url}: HTTP ${res.status}`)
  }
  return res.json() as Promise<AgentJson>
}
