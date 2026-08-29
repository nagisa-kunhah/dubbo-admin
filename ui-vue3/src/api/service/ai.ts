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

import axios, { type InternalAxiosRequestConfig } from 'axios'
import { AccessTokenManager, accessTokenManager } from '@/auth/accessToken'

const BASE_URL = '/api/v1'

export interface Session {
  session_id: string
  created_at: string
  updated_at: string
  message_count: number
  status: string
}

export interface ChatMessage {
  id: string
  content: string
  role: 'user' | 'assistant'
  timestamp: number
  type?: 'normal' | 'error' | 'partial_error'
}

export interface ChatResponse {
  data: {
    session_id: string
    messages: ChatMessage[]
  }
}

type RetryConfig = InternalAxiosRequestConfig & { _aiAuthRetried?: boolean }

const aiClient = axios.create({ baseURL: `${BASE_URL}/ai` })

aiClient.interceptors.request.use(async (config) => {
  const token = await accessTokenManager.getToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

aiClient.interceptors.response.use(undefined, async (error) => {
  const config = error.config as RetryConfig | undefined
  const challenge = error.response?.headers?.['www-authenticate']
  if (
    accessTokenManager.isEnabled() &&
    error.response?.status === 401 &&
    typeof challenge === 'string' &&
    challenge.toLowerCase().includes('bearer') &&
    config &&
    !config._aiAuthRetried
  ) {
    config._aiAuthRetried = true
    accessTokenManager.clear()
    const token = await accessTokenManager.getToken(true)
    if (token) config.headers.Authorization = `Bearer ${token}`
    return aiClient.request(config)
  }
  return Promise.reject(error)
})

export async function authenticatedFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
  manager: AccessTokenManager = accessTokenManager,
  fetcher: typeof fetch = fetch
): Promise<Response> {
  const execute = async (retried: boolean): Promise<Response> => {
    const token = await manager.getToken(retried)
    const headers = new Headers(init.headers)
    if (token) headers.set('Authorization', `Bearer ${token}`)
    const response = await fetcher(input, { ...init, headers })
    if (
      !retried &&
      manager.isEnabled() &&
      response.status === 401 &&
      response.headers.get('WWW-Authenticate')?.toLowerCase().includes('bearer')
    ) {
      manager.clear()
      return execute(true)
    }
    return response
  }
  return execute(false)
}

export const aiService = {
  async createSession(): Promise<string> {
    const response = await aiClient.post('/sessions')
    return response.data.data.session_id
  },

  async getSessions(): Promise<Session[]> {
    const response = await aiClient.get('/sessions')
    return response.data.data.sessions || []
  },

  async getSessionInfo(sessionId: string): Promise<ChatResponse> {
    const response = await aiClient.get(`/sessions/${sessionId}`)
    return response.data
  },

  async deleteSession(sessionId: string): Promise<void> {
    await aiClient.delete(`/sessions/${sessionId}`)
  },

  async sendChatMessage(message: string, sessionId?: string): Promise<ReadableStream> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (sessionId) headers['X-Session-ID'] = sessionId
    const response = await authenticatedFetch(`${BASE_URL}/ai/chat/stream`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ message, sessionID: sessionId }),
      mode: 'cors',
      credentials: 'omit'
    })
    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`)
    return response.body!
  }
}

export default aiService
