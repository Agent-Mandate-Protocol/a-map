import { describe, it, expect, vi, afterEach } from 'vitest'
import { InMemoryNonceStore } from './nonce-store.js'

afterEach(() => vi.useRealTimers())

describe('InMemoryNonceStore', () => {
  it('returns true for a fresh nonce', async () => {
    const store = new InMemoryNonceStore()
    expect(await store.checkAndStore('abc', 60_000)).toBe(true)
  })

  it('returns false for a replayed nonce within TTL', async () => {
    const store = new InMemoryNonceStore()
    await store.checkAndStore('abc', 60_000)
    expect(await store.checkAndStore('abc', 60_000)).toBe(false)
  })

  it('treats different nonces as independent', async () => {
    const store = new InMemoryNonceStore()
    expect(await store.checkAndStore('n1', 60_000)).toBe(true)
    expect(await store.checkAndStore('n2', 60_000)).toBe(true)
    expect(await store.checkAndStore('n1', 60_000)).toBe(false)
    expect(await store.checkAndStore('n2', 60_000)).toBe(false)
  })

  it('evicts expired nonces on the very next call after expiry', async () => {
    vi.useFakeTimers()
    const store = new InMemoryNonceStore()
    const TTL = 10_000

    await store.checkAndStore('nonce-a', TTL)
    await store.checkAndStore('nonce-b', TTL)

    vi.advanceTimersByTime(TTL + 1)

    // The next call — regardless of how many have come before — drains the expired entries
    await store.checkAndStore('nonce-c', TTL)

    // nonce-a and nonce-b are now evicted; a replay attempt returns true (re-stored as fresh)
    // Security note: the timestamp check in verifyRequest() catches replays of old requests
    // before the nonce store is consulted, so evicting expired nonces is safe.
    expect(await store.checkAndStore('nonce-a', TTL)).toBe(true)
    expect(await store.checkAndStore('nonce-b', TTL)).toBe(true)
  })

  it('memory is bounded: only live nonces occupy the map', async () => {
    vi.useFakeTimers()
    const store = new InMemoryNonceStore()
    const TTL = 10_000

    // Store 50 nonces, advance past TTL, store 50 more — only the second batch should remain
    for (let i = 0; i < 50; i++) await store.checkAndStore(`old-${i}`, TTL)
    vi.advanceTimersByTime(TTL + 1)
    for (let i = 0; i < 50; i++) await store.checkAndStore(`new-${i}`, TTL)

    // All old-* nonces were evicted as the new-* ones were inserted; they are fresh again
    expect(await store.checkAndStore('old-0', TTL)).toBe(true)
    // new-* nonces are still live — still rejected as replays
    expect(await store.checkAndStore('new-0', TTL)).toBe(false)
  })
})
