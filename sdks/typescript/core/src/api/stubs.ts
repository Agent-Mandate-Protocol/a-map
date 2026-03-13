import type { DelegationToken } from '../types/token.js'
import type { VerificationResult } from '../types/result.js'
import type {
  IssueOptions,
  DelegateOptions,
  VerifyOptions,
  SignRequestOptions,
  SignedRequestHeaders,
  VerifyRequestOptions,
} from './types.js'

export async function issue(_opts: IssueOptions): Promise<DelegationToken> {
  throw new Error('Not implemented')
}

export async function delegate(_opts: DelegateOptions): Promise<DelegationToken> {
  throw new Error('Not implemented')
}

export async function verify(
  _chain: DelegationToken[],
  _opts: VerifyOptions,
): Promise<VerificationResult> {
  throw new Error('Not implemented')
}

export function signRequest(_opts: SignRequestOptions): SignedRequestHeaders {
  throw new Error('Not implemented')
}

export async function verifyRequest(
  _opts: VerifyRequestOptions,
): Promise<VerificationResult> {
  throw new Error('Not implemented')
}

export async function revoke(_did: string, _privateKey: string): Promise<void> {
  throw new Error('Not implemented')
}
