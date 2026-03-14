import type { Constraints } from '../types/constraints.js'

/**
 * Named constraint presets for common agent use cases.
 *
 * Spread into constraints when issuing a mandate to quickly apply
 * a sensible default, then override specific fields as needed.
 *
 * Usage:
 *   const token = await amap.issue({
 *     principal: humanDid,
 *     delegate: agentDid,
 *     permissions: ['shell.exec'],
 *     constraints: {
 *       ...amap.presets.Developer,
 *       allowedDomains: ['~/projects/my-app/**'],  // narrow further
 *     },
 *     expiresIn: '2h',
 *     privateKey,
 *   })
 */
export const AmapPresets = {

  /**
   * Read-only access to common inspection commands.
   * No write access. Safe for untrusted analysis agents.
   * Everything not in allowedActions is implicitly denied.
   */
  ReadOnly: {
    allowedActions: [
      'ls', 'cat', 'find', 'grep', 'head', 'tail',
      'git status', 'git log', 'git diff', 'git show',
      'npm list', 'echo', 'pwd', 'whoami', 'env',
    ],
    readOnly: true,
    maxCalls: 500,
  } satisfies Constraints,

  /**
   * Full autonomy except catastrophic and irreversible operations.
   * The recommended preset for trusted coding agents.
   * Blocks: rm -rf, sudo, force push, database drops, cloud destroy.
   */
  Developer: {
    allowedActions: ['*'] as ['*'],
    deniedActions: [
      'rm -rf', 'sudo rm', 'sudo su', 'sudo bash', 'sudo sh',
      'chmod 777', 'chown root', 'chattr',
      'dd if=/dev/zero', 'dd if=/dev/null', 'mkfs', 'fdisk', 'parted',
      'shutdown', 'reboot', 'halt', 'poweroff',
      'git push --force', 'git push -f',
      'kubectl delete', 'kubectl drain', 'helm uninstall',
      'terraform destroy', 'terraform apply -destroy',
      'DROP TABLE', 'DROP DATABASE', 'TRUNCATE', 'DELETE FROM',
      ':(){:|:&};:',
    ],
    deniedDomains: [
      '~/.ssh/**', '~/.aws/**', '~/.gnupg/**',
      '~/.config/gcloud/**', '~/.azure/**',
      '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    ],
    maxCalls: 500,
  } satisfies Constraints,

  /**
   * CI/CD pipeline operations only.
   * Build, test, deploy. No destructive cluster ops.
   */
  CiCd: {
    allowedActions: [
      'npm', 'yarn', 'pnpm', 'git',
      'docker build', 'docker push',
      'kubectl apply', 'helm upgrade',
    ],
    deniedActions: [
      'kubectl delete', 'kubectl drain', 'helm uninstall',
      'docker system prune', 'rm', 'sudo',
    ],
    maxCalls: 100,
    rateLimit: { count: 20, windowSeconds: 60 },
  } satisfies Constraints,

  /**
   * Maximum autonomy — only the most catastrophic operations blocked.
   * For highly trusted, fully autonomous agents where Developer is too restrictive.
   * Use with caution.
   */
  GodMode: {
    allowedActions: ['*'] as ['*'],
    deniedActions: [
      'rm -rf /', 'rm -rf ~', 'sudo rm -rf',
      'mkfs', 'dd if=/dev/zero of=/dev/sd',
      'shutdown', 'reboot', 'halt',
      ':(){:|:&};:',
    ],
  } satisfies Constraints,

} as const
