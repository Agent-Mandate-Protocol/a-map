export { default as register, createAmapPlugin } from './plugin.js'
export type { AmapPluginOptions } from './plugin.js'

export { SessionMandateStore } from './session-store.js'

export { beforeToolCall } from './hook.js'
export type { HookContext, HookOptions } from './hook.js'

export { amapRegisterSessionToolDefinition, handleAmapRegisterSession } from './tools/amap-register-session.js'
export { amapIssueToolDefinition, handleAmapIssue } from './tools/amap-issue.js'
