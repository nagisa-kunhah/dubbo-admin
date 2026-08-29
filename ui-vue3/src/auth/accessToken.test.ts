/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { describe, expect, it, vi } from 'vitest'
import { AccessTokenManager } from './accessToken'

function tokenWithExpiry(exp: number): string {
  const payload = btoa(JSON.stringify({ exp }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
  return `header.${payload}.signature`
}

describe('AccessTokenManager', () => {
  it('does not issue tokens while capability is disabled', async () => {
    const issue = vi.fn(async () => tokenWithExpiry(Date.now() / 1000 + 3600))
    const manager = new AccessTokenManager(issue)
    await expect(manager.getToken()).resolves.toBeUndefined()
    expect(issue).not.toHaveBeenCalled()
  })

  it('refreshes missing or near-expiry tokens and shares the in-flight promise', async () => {
    let resolveIssue: (token: string) => void = () => undefined
    const issue = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          resolveIssue = resolve
        })
    )
    const manager = new AccessTokenManager(issue)
    manager.setEnabled(true)
    const first = manager.getToken()
    const second = manager.getToken()
    expect(issue).toHaveBeenCalledTimes(1)
    const token = tokenWithExpiry(Math.floor(Date.now() / 1000) + 120)
    resolveIssue(token)
    await expect(Promise.all([first, second])).resolves.toEqual([token, token])

    manager.setTokenForTest(tokenWithExpiry(Math.floor(Date.now() / 1000) + 30))
    const refresh = manager.getToken()
    expect(issue).toHaveBeenCalledTimes(2)
    resolveIssue(token)
    await refresh
  })

  it('clears runtime state without touching browser persistence', () => {
    const localSpy = vi.spyOn(Storage.prototype, 'setItem')
    const manager = new AccessTokenManager(async () => tokenWithExpiry(1))
    manager.setEnabled(true)
    manager.setTokenForTest(tokenWithExpiry(9999999999))
    manager.clear()
    expect(manager.peek()).toBeUndefined()
    expect(localSpy).not.toHaveBeenCalled()
  })

  it('does not let an abandoned refresh clear a newer in-flight refresh', async () => {
    const resolvers: Array<(token: string) => void> = []
    const issue = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          resolvers.push(resolve)
        })
    )
    const manager = new AccessTokenManager(issue)
    manager.setEnabled(true)

    const abandoned = manager.getToken()
    manager.clear()
    const current = manager.getToken()
    expect(issue).toHaveBeenCalledTimes(2)

    const abandonedToken = tokenWithExpiry(Math.floor(Date.now() / 1000) + 120)
    resolvers[0](abandonedToken)
    await expect(abandoned).resolves.toBe(abandonedToken)

    const concurrent = manager.getToken()
    expect(issue).toHaveBeenCalledTimes(2)
    const currentToken = tokenWithExpiry(Math.floor(Date.now() / 1000) + 240)
    resolvers[1](currentToken)
    await expect(Promise.all([current, concurrent])).resolves.toEqual([currentToken, currentToken])
    expect(manager.peek()).toBe(currentToken)
  })
})
