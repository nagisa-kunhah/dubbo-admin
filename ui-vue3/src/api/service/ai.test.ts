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
import { AccessTokenManager } from '@/auth/accessToken'
import { authenticatedFetch } from './ai'

describe('authenticatedFetch', () => {
  it('keeps anonymous compatibility when access token is disabled', async () => {
    const manager = new AccessTokenManager(async () => 'unused')
    const fetcher = vi.fn(
      async (_input: RequestInfo | URL, init?: RequestInit) =>
        new Response(JSON.stringify(init?.headers ?? {}), { status: 200 })
    )
    await authenticatedFetch('/api/v1/ai/test', {}, manager, fetcher)
    expect(fetcher).toHaveBeenCalledTimes(1)
    expect(
      (fetcher.mock.calls[0][1]?.headers as Record<string, string> | undefined)?.Authorization
    ).toBeUndefined()
  })

  it('refreshes a Bearer 401 and retries only once', async () => {
    const issue = vi.fn().mockResolvedValueOnce('first-token').mockResolvedValueOnce('second-token')
    const manager = new AccessTokenManager(issue)
    manager.setEnabled(true)
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        new Response('', { status: 401, headers: { 'WWW-Authenticate': 'Bearer' } })
      )
      .mockResolvedValueOnce(new Response('', { status: 200 }))
    const response = await authenticatedFetch('/api/v1/ai/test', {}, manager, fetcher)
    expect(response.status).toBe(200)
    expect(issue).toHaveBeenCalledTimes(2)
    expect(fetcher).toHaveBeenCalledTimes(2)
    expect(new Headers(fetcher.mock.calls[1][1]?.headers).get('Authorization')).toBe(
      'Bearer second-token'
    )
  })

  it('does not refresh 403', async () => {
    const issue = vi.fn().mockResolvedValue('token')
    const manager = new AccessTokenManager(issue)
    manager.setEnabled(true)
    const fetcher = vi.fn(async () => new Response('', { status: 403 }))
    const response = await authenticatedFetch('/api/v1/ai/test', {}, manager, fetcher)
    expect(response.status).toBe(403)
    expect(issue).toHaveBeenCalledTimes(1)
    expect(fetcher).toHaveBeenCalledTimes(1)
  })
})
