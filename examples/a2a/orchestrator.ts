import { amap } from '../../sdks/typescript/core/src/index.js'
import type { DelegationToken } from '../../sdks/typescript/core/src/index.js'
import { orchestratorDid, orchestratorKeys, workerDid } from './shared.js'

export class ResearchOrchestrator {
  private mandateChain: DelegationToken[] = []

  async startProject(humanMandate: DelegationToken[]): Promise<void> {
    this.mandateChain = humanMandate
    console.log('[Orchestrator] Project started. Alice authorised up to $100.')
  }

  /**
   * Sub-delegates a narrowed mandate to the worker.
   * Permissions can only narrow (web:read ⊆ parent permissions).
   * Constraints can only tighten (maxSpend: 10 ≤ parent maxSpend: 100).
   * Returns the full chain: [Alice→Orchestrator, Orchestrator→Worker]
   */
  async hireWorker(): Promise<DelegationToken[]> {
    console.log('[Orchestrator] Delegating to worker — slicing $10 from the $100 mandate...')

    const workerToken = await amap.delegate({
      parentToken: this.mandateChain[this.mandateChain.length - 1]!,
      parentChain: this.mandateChain,
      delegate: workerDid,
      permissions: ['web:read'],      // narrowed from ['web:read', 'crm:write']
      constraints: { maxSpend: 10 }, // tightened from maxSpend: 100
      expiresIn: '15m',
      privateKey: orchestratorKeys.privateKey,
    })

    return [...this.mandateChain, workerToken]
  }
}
