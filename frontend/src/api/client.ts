export type AuthStatus = {
  needsSetup: boolean
  authenticated: boolean
  setupTokenRequired?: boolean
}

let csrfToken = ''

export function getCsrfToken(): string {
  return csrfToken
}

function apiErrorMessage(response: Response, body: Record<string, unknown>): string {
  if (typeof body?.error === 'string' && body.error.trim()) {
    return body.error
  }
  if (response.status === 404) {
    return 'プロンプト API が見つかりません。vulndock-customized を最新版でビルドし、プロセスを再起動してください。'
  }
  if (response.status === 401) {
    return 'ログインが必要です。ページを再読み込みしてログインしてください。'
  }
  return response.statusText || 'request failed'
}

async function parseJSON<T>(response: Response): Promise<T> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>
  if (!response.ok) {
    throw new Error(apiErrorMessage(response, body))
  }
  return body as T
}

export async function fetchAuthStatus(): Promise<AuthStatus> {
  return parseJSON(await fetch('/api/auth/status', { credentials: 'include' }))
}

export async function setupAccount(password: string, setupToken?: string): Promise<void> {
  const payload: { password: string; setupToken?: string } = { password }
  if (setupToken?.trim()) {
    payload.setupToken = setupToken.trim()
  }
  const body = await parseJSON<{ csrfToken: string }>(
    await fetch('/api/auth/setup', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  )
  csrfToken = body.csrfToken
}

export async function login(password: string): Promise<void> {
  const body = await parseJSON<{ csrfToken: string }>(
    await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    }),
  )
  csrfToken = body.csrfToken
}

export async function logout(): Promise<void> {
  await parseJSON(
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': csrfToken },
    }),
  )
  csrfToken = ''
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  const body = await parseJSON<{ csrfToken: string }>(
    await fetch('/api/auth/change-password', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ currentPassword, newPassword }),
    }),
  )
  csrfToken = body.csrfToken
}

export type SavedPrompt = {
  id: string
  title: string
  body: string
  createdAt: string
  updatedAt: string
}

export async function listSavedPrompts(): Promise<SavedPrompt[]> {
  const data = await parseJSON<unknown>(await fetch('/api/prompts', { credentials: 'include' }))
  return Array.isArray(data) ? (data as SavedPrompt[]) : []
}

export async function saveSavedPrompt(draft: {
  id?: string
  title: string
  body: string
}): Promise<SavedPrompt> {
  const isNew = !draft.id
  const url = isNew ? '/api/prompts' : `/api/prompts/${encodeURIComponent(draft.id!)}`
  const method = isNew ? 'POST' : 'PUT'
  return parseJSON(
    await fetch(url, {
      method,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify(draft),
    }),
  )
}

export async function deleteSavedPrompt(id: string): Promise<void> {
  await parseJSON(
    await fetch(`/api/prompts/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: { 'X-CSRF-Token': csrfToken },
    }),
  )
}

export async function listReports(): Promise<unknown[]> {
  const data = await parseJSON<unknown>(await fetch('/api/reports', { credentials: 'include' }))
  return Array.isArray(data) ? data : []
}

export async function saveReport(draft: unknown, isNew: boolean, id?: string): Promise<unknown> {
  const url = isNew || !id ? '/api/reports' : `/api/reports/${encodeURIComponent(id)}`
  const method = isNew || !id ? 'POST' : 'PUT'
  return parseJSON(
    await fetch(url, {
      method,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify(draft),
    }),
  )
}

export async function listTrashReports(): Promise<unknown[]> {
  const data = await parseJSON<unknown>(await fetch('/api/reports/trash', { credentials: 'include' }))
  return Array.isArray(data) ? data : []
}

export async function restoreReportFromTrash(id: string): Promise<void> {
  await parseJSON(
    await fetch(`/api/reports/${encodeURIComponent(id)}/restore`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': csrfToken },
    }),
  )
}

export async function deleteReport(id: string): Promise<void> {
  await parseJSON(
    await fetch(`/api/reports/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      credentials: 'include',
      headers: { 'X-CSRF-Token': csrfToken },
    }),
  )
}

export function attachmentURL(reportId: string, fileId: string): string {
  return `/api/reports/${encodeURIComponent(reportId)}/attachments/${encodeURIComponent(fileId)}`
}

export async function fetchHealth(): Promise<{ version: string }> {
  return parseJSON(await fetch('/api/health'))
}

export async function fetchServerInfo(): Promise<{ dataDir: string; dbBytes?: number }> {
  return parseJSON(await fetch('/api/server/info', { credentials: 'include' }))
}

export async function createEncryptedBackup(password: string): Promise<{ fileName: string; data: string }> {
  return parseJSON(
    await fetch('/api/backup/export', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ password }),
    }),
  )
}

export async function restoreEncryptedBackup(archiveData: string, password: string): Promise<unknown[]> {
  const data = await parseJSON<unknown>(
    await fetch('/api/backup/restore', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ password, data: archiveData }),
    }),
  )
  return Array.isArray(data) ? data : []
}
