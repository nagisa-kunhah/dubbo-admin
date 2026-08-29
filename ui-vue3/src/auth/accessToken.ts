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

import request from '@/base/http/request'

type TokenIssuer = () => Promise<string>

const REFRESH_SKEW_SECONDS = 60

export class AccessTokenManager {
  private enabled = false
  private token: string | undefined
  private refreshPromise: Promise<string> | undefined
  private generation = 0

  constructor(private readonly issue: TokenIssuer) {}

  setEnabled(enabled: boolean): void {
    this.enabled = enabled
    if (!enabled) this.clear()
  }

  isEnabled(): boolean {
    return this.enabled
  }

  async getToken(forceRefresh = false): Promise<string | undefined> {
    if (!this.enabled) return undefined
    if (!forceRefresh && this.token && tokenExpiresAfter(this.token, REFRESH_SKEW_SECONDS)) {
      return this.token
    }
    if (!this.refreshPromise) {
      const generation = this.generation
      const refresh = this.issue()
        .then((token) => {
          if (!token) throw new Error('Admin returned an empty AI access token')
          if (generation === this.generation) this.token = token
          return token
        })
        .finally(() => {
          if (this.refreshPromise === refresh) this.refreshPromise = undefined
        })
      this.refreshPromise = refresh
    }
    return this.refreshPromise
  }

  clear(): void {
    this.generation++
    this.token = undefined
    this.refreshPromise = undefined
  }

  peek(): string | undefined {
    return this.token
  }

  setTokenForTest(token: string): void {
    this.token = token
  }
}

function tokenExpiresAfter(token: string, seconds: number): boolean {
  try {
    const payload = token.split('.')[1]
    if (!payload) return false
    const normalized = payload.replace(/-/g, '+').replace(/_/g, '/')
    const padding = '='.repeat((4 - (normalized.length % 4)) % 4)
    const claims = JSON.parse(atob(normalized + padding)) as { exp?: number }
    return typeof claims.exp === 'number' && claims.exp > Date.now() / 1000 + seconds
  } catch {
    return false
  }
}

async function issueFromAdmin(): Promise<string> {
  const response = await request({ url: '/auth/token', method: 'post' })
  return response.data.accessToken
}

export const accessTokenManager = new AccessTokenManager(issueFromAdmin)
