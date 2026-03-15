import { describe, it, expect } from 'vitest'
import {
  register,
  createAmapPlugin,
  SessionMandateStore,
  beforeToolCall,
  amapRegisterSessionToolDefinition,
  handleAmapRegisterSession,
  amapIssueToolDefinition,
  handleAmapIssue,
} from './index.js'

describe('@agentmandateprotocol/openclaw exports', () => {
  it('exports register (default OpenClaw entry point)', () => expect(register).toBeTypeOf('function'))
  it('exports createAmapPlugin', () => expect(createAmapPlugin).toBeTypeOf('function'))
  it('exports SessionMandateStore', () => expect(SessionMandateStore).toBeTypeOf('function'))
  it('exports beforeToolCall', () => expect(beforeToolCall).toBeTypeOf('function'))
  it('exports amapRegisterSessionToolDefinition', () => {
    expect(amapRegisterSessionToolDefinition.name).toBe('amap_register_session')
  })
  it('exports handleAmapRegisterSession', () => expect(handleAmapRegisterSession).toBeTypeOf('function'))
  it('exports amapIssueToolDefinition', () => {
    expect(amapIssueToolDefinition.name).toBe('amap_issue')
  })
  it('exports handleAmapIssue', () => expect(handleAmapIssue).toBeTypeOf('function'))
})

describe('createAmapPlugin()', () => {
  it('returns a valid plugin object', () => {
    const plugin = createAmapPlugin()
    expect(plugin.name).toBe('@agentmandateprotocol/openclaw')
    expect(plugin.tools).toHaveLength(2)
    expect(plugin.tools.map(t => t.name)).toContain('amap_issue')
    expect(plugin.tools.map(t => t.name)).toContain('amap_register_session')
    expect(plugin.beforeToolCall).toBeTypeOf('function')
    expect(plugin.handleTool).toBeTypeOf('function')
  })

  it('passes amap_register_session through beforeToolCall without verification', async () => {
    const plugin = createAmapPlugin()
    const input = { chain: [], headers: {} }
    const result = await plugin.beforeToolCall('amap_register_session', input, { sessionId: 'session-1' })
    expect(result).toBe(input)
  })

  it('passes amap_issue through beforeToolCall without verification', async () => {
    const plugin = createAmapPlugin()
    const input = { principal: 'alice', agentDid: 'did:...', permissions: [], expiresIn: '1h', issuerPrivateKey: 'x' }
    const result = await plugin.beforeToolCall('amap_issue', input, { sessionId: 'session-1' })
    expect(result).toBe(input)
  })
})

describe('register(api) — OpenClaw plugin entry point', () => {
  it('calls api.registerTool for amap_issue and amap_register_session', () => {
    const registeredTools: string[] = []
    const hookNames: string[] = []
    const mockApi = {
      config: {},
      logger: { warn: () => {} },
      registerTool: (def: { name: string }) => { registeredTools.push(def.name) },
      on: (event: string) => { hookNames.push(event) },
    }
    register(mockApi as never)
    expect(registeredTools).toContain('amap_issue')
    expect(registeredTools).toContain('amap_register_session')
    expect(hookNames).toContain('before_tool_call')
  })

  it('before_tool_call hook returns { abort: false } for amap_register_session', async () => {
    let hookHandler: (e: unknown, ctx: unknown) => Promise<{ abort: boolean }>
    const mockApi = {
      config: {},
      logger: { warn: () => {} },
      registerTool: () => {},
      on: (_: string, h: typeof hookHandler) => { hookHandler = h },
    }
    register(mockApi as never)
    const result = await hookHandler!(
      {},
      { toolName: 'amap_register_session', sessionKey: 'session-1', args: {} },
    )
    expect(result).toEqual({ abort: false })
  })

  it('before_tool_call hook returns { abort: true } when no mandate registered', async () => {
    let hookHandler: (e: unknown, ctx: unknown) => Promise<{ abort: boolean; error?: string }>
    const mockApi = {
      config: {},
      logger: { warn: () => {} },
      registerTool: () => {},
      on: (_: string, h: typeof hookHandler) => { hookHandler = h },
    }
    register(mockApi as never)
    const result = await hookHandler!(
      {},
      { toolName: 'some_tool', sessionKey: 'session-1', args: {} },
    )
    expect(result.abort).toBe(true)
    expect(result.error).toContain('BROKEN_CHAIN')
  })
})
