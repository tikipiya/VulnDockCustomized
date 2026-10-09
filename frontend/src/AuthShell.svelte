<script lang="ts">
  import { onMount } from 'svelte'
  import type { Snippet } from 'svelte'
  import {
    changePassword,
    fetchAuthStatus,
    login,
    logout,
    setupAccount,
  } from './api/client'

  type Mode = 'loading' | 'setup' | 'login' | 'app'

  let {
    children,
  }: {
    children: Snippet
  } = $props()

  let mode = $state<Mode>('loading')
  let password = $state('')
  let setupToken = $state('')
  let setupTokenRequired = $state(false)
  let errorMessage = $state('')
  let showChangePassword = $state(false)
  let currentPassword = $state('')
  let newPassword = $state('')

  onMount(() => {
    void refreshStatus()
  })

  async function refreshStatus() {
    errorMessage = ''
    try {
      const status = await fetchAuthStatus()
      if (status.needsSetup) {
        setupTokenRequired = Boolean(status.setupTokenRequired)
        mode = 'setup'
        return
      }
      mode = status.authenticated ? 'app' : 'login'
    } catch {
      errorMessage = 'サーバーに接続できません'
      mode = 'login'
    }
  }

  async function submitSetup() {
    errorMessage = ''
    try {
      await setupAccount(password, setupTokenRequired ? setupToken : undefined)
      password = ''
      setupToken = ''
      mode = 'app'
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : 'セットアップに失敗しました'
    }
  }

  async function submitLogin() {
    errorMessage = ''
    try {
      await login(password)
      password = ''
      mode = 'app'
    } catch {
      errorMessage = 'パスワードが正しくありません'
    }
  }

  async function submitChangePassword() {
    errorMessage = ''
    try {
      await changePassword(currentPassword, newPassword)
      currentPassword = ''
      newPassword = ''
      showChangePassword = false
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : 'パスワード変更に失敗しました'
    }
  }

  async function handleLogout() {
    await logout()
    mode = 'login'
  }
</script>

{#if mode === 'loading'}
  <div class="auth-shell">読み込み中…</div>
{:else if mode === 'setup'}
  <div class="auth-shell">
    <h1>VulnDockCustomized 初期設定</h1>
    <p>管理者パスワードを設定してください（8文字以上）。</p>
    {#if setupTokenRequired}
      <p>初回セットアップには <code>VULNDOCK_SETUP_TOKEN</code>（未設定時はデータディレクトリの <code>.setup-token</code>）が必要です。プロキシ経由ではループバック信頼は使えません。同一マシンへ直接 <code>127.0.0.1</code> で繋ぐ開発時のみ <code>VULNDOCK_TRUST_LOOPBACK_SETUP=true</code> で省略できます。</p>
    {/if}
    {#if errorMessage}<p class="auth-error">{errorMessage}</p>{/if}
    <form
      onsubmit={(e) => {
        e.preventDefault()
        void submitSetup()
      }}
    >
      {#if setupTokenRequired}
        <input
          type="text"
          bind:value={setupToken}
          autocomplete="off"
          placeholder="セットアップトークン"
          required
        />
      {/if}
      <input type="password" bind:value={password} autocomplete="new-password" required minlength="8" />
      <button type="submit">セットアップ完了</button>
    </form>
  </div>
{:else if mode === 'login'}
  <div class="auth-shell">
    <h1>VulnDockCustomized</h1>
    {#if errorMessage}<p class="auth-error">{errorMessage}</p>{/if}
    <form
      onsubmit={(e) => {
        e.preventDefault()
        void submitLogin()
      }}
    >
      <input type="password" bind:value={password} autocomplete="current-password" required />
      <button type="submit">ログイン</button>
    </form>
  </div>
{:else}
  <div class="app-with-session">
    <div class="session-bar">
      <button type="button" class="linkish" onclick={() => (showChangePassword = !showChangePassword)}>
        パスワード変更
      </button>
      <button type="button" class="linkish" onclick={() => void handleLogout()}>ログアウト</button>
    </div>
    {#if showChangePassword}
      <form
        class="change-password"
        onsubmit={(e) => {
          e.preventDefault()
          void submitChangePassword()
        }}
      >
        <input type="password" placeholder="現在のパスワード" bind:value={currentPassword} required />
        <input type="password" placeholder="新しいパスワード" bind:value={newPassword} required minlength="8" />
        <button type="submit">変更</button>
      </form>
      {#if errorMessage}<p class="auth-error">{errorMessage}</p>{/if}
    {/if}
    {@render children()}
  </div>
{/if}

<style>
  .auth-shell {
    max-width: 24rem;
    margin: 4rem auto;
    padding: 1.5rem;
    display: grid;
    gap: 0.75rem;
  }
  .auth-error {
    color: #f87171;
  }
  .session-bar {
    display: flex;
    gap: 0.75rem;
    justify-content: flex-end;
    padding: 0.5rem 1rem;
    font-size: 0.875rem;
  }
  .linkish {
    background: none;
    border: none;
    color: #93c5fd;
    cursor: pointer;
    text-decoration: underline;
  }
  .change-password {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    padding: 0 1rem 0.5rem;
  }
</style>
