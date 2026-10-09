<script lang="ts">
  import {
    deleteSavedPrompt,
    listSavedPrompts,
    saveSavedPrompt,
    type SavedPrompt,
  } from './api/client'

  let {
    reloadSignal = 0,
  }: {
    reloadSignal?: number
  } = $props()

  let open = $state(false)
  let loading = $state(false)
  let copyMessage = $state('')
  let errorMessage = $state('')
  let prompts = $state<SavedPrompt[]>([])
  let selectedId = $state('')
  let draftTitle = $state('')
  let draftBody = $state('')
  let saving = $state(false)
  let savedSnapshot = $state({ title: '', body: '' })

  let selectedPrompt = $derived(prompts.find((p) => p.id === selectedId))

  $effect(() => {
    if (reloadSignal > 0) {
      void loadPrompts()
    }
  })

  function syncSnapshot() {
    savedSnapshot = { title: draftTitle, body: draftBody }
  }

  function isDirty() {
    return draftTitle !== savedSnapshot.title || draftBody !== savedSnapshot.body
  }

  function confirmDiscard() {
    if (!isDirty()) {
      return true
    }
    return confirm('未保存の変更を破棄しますか？')
  }

  async function loadPrompts() {
    loading = true
    errorMessage = ''
    try {
      prompts = await listSavedPrompts()
      if (!selectedId && prompts.length > 0) {
        selectPrompt(prompts[0].id, { skipDiscardCheck: true })
      } else if (selectedId) {
        const current = prompts.find((p) => p.id === selectedId)
        if (current) {
          selectPrompt(current.id, { skipDiscardCheck: true })
        } else if (prompts.length > 0) {
          selectPrompt(prompts[0].id, { skipDiscardCheck: true })
        } else {
          startNewPrompt({ skipDiscardCheck: true })
        }
      }
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : 'プロンプトの読み込みに失敗しました'
    } finally {
      loading = false
    }
  }

  async function toggleOpen() {
    open = !open
    if (open) {
      await loadPrompts()
    }
  }

  function selectPrompt(id: string, options: { skipDiscardCheck?: boolean } = {}) {
    if (!options.skipDiscardCheck && !confirmDiscard()) {
      return
    }
    selectedId = id
    const item = prompts.find((p) => p.id === id)
    if (item) {
      draftTitle = item.title
      draftBody = item.body
      syncSnapshot()
    }
  }

  function startNewPrompt(options: { skipDiscardCheck?: boolean } = {}) {
    if (!options.skipDiscardCheck && !confirmDiscard()) {
      return
    }
    selectedId = ''
    draftTitle = ''
    draftBody = ''
    syncSnapshot()
  }

  async function persistPrompt() {
    saving = true
    copyMessage = ''
    errorMessage = ''
    try {
      const saved = await saveSavedPrompt({
        id: selectedId || undefined,
        title: draftTitle,
        body: draftBody,
      })
      const index = prompts.findIndex((p) => p.id === saved.id)
      if (index >= 0) {
        prompts = prompts.map((p) => (p.id === saved.id ? saved : p))
      } else {
        prompts = [saved, ...prompts]
      }
      selectPrompt(saved.id, { skipDiscardCheck: true })
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : '保存に失敗しました'
    } finally {
      saving = false
    }
  }

  async function removePrompt() {
    if (!selectedId) {
      return
    }
    if (!confirm('このプロンプトを削除しますか？')) {
      return
    }
    errorMessage = ''
    try {
      await deleteSavedPrompt(selectedId)
      prompts = prompts.filter((p) => p.id !== selectedId)
      if (prompts.length > 0) {
        selectPrompt(prompts[0].id, { skipDiscardCheck: true })
      } else {
        startNewPrompt({ skipDiscardCheck: true })
      }
    } catch (error) {
      errorMessage = error instanceof Error ? error.message : '削除に失敗しました'
    }
  }

  async function copyBody() {
    const text = draftBody.trim()
    if (!text) {
      return
    }
    try {
      await navigator.clipboard.writeText(text)
      copyMessage = 'コピーしました'
      window.setTimeout(() => {
        copyMessage = ''
      }, 2000)
    } catch {
      copyMessage = 'コピーに失敗しました'
    }
  }
</script>

<div class="prompt-shelf">
  <button class="ghost-button prompt-toggle" type="button" onclick={() => void toggleOpen()}>
    {open ? 'プロンプトを閉じる' : '保存プロンプト'}
  </button>

  {#if open}
    <div class="prompt-panel" aria-label="保存プロンプト">
      {#if loading}
        <p class="muted">読み込み中…</p>
      {:else}
        {#if errorMessage}
          <p class="prompt-error">{errorMessage}</p>
        {/if}
        <div class="prompt-list">
          {#each prompts as item (item.id)}
            <button
              class="prompt-list-item"
              class:active={item.id === selectedId}
              type="button"
              onclick={() => selectPrompt(item.id)}
            >
              {item.title}
            </button>
          {/each}
          <button class="small-button" type="button" onclick={() => startNewPrompt()}>＋ 新規</button>
        </div>

        <label class="prompt-field">
          タイトル
          <input bind:value={draftTitle} placeholder="例: 初回返信テンプレ" />
        </label>
        <label class="prompt-field">
          本文
          <textarea bind:value={draftBody} rows="8" placeholder="コピーして使うプロンプト本文"></textarea>
        </label>

        <div class="prompt-actions">
          <button class="primary-button" type="button" onclick={() => void persistPrompt()} disabled={saving}>
            {saving ? '保存中…' : '保存'}
          </button>
          <button class="ghost-button" type="button" onclick={() => void copyBody()} disabled={!draftBody.trim()}>
            コピー
          </button>
          {#if selectedId}
            <button class="ghost-button" type="button" onclick={() => void removePrompt()}>削除</button>
          {/if}
        </div>
        {#if copyMessage}
          <p class="muted">{copyMessage}</p>
        {/if}
        {#if selectedPrompt}
          <p class="muted prompt-meta">更新: {selectedPrompt.updatedAt.replace('T', ' ').slice(0, 16)}</p>
        {/if}
      {/if}
    </div>
  {/if}
</div>

<style>
  .prompt-shelf {
    display: grid;
    gap: 8px;
  }
  .prompt-toggle {
    width: 100%;
    justify-content: center;
  }
  .prompt-panel {
    display: grid;
    gap: 8px;
    padding: 8px;
    border: 1px solid rgba(148, 163, 184, 0.25);
    border-radius: 8px;
    background: rgba(15, 23, 42, 0.35);
  }
  .prompt-error {
    color: #f87171;
    font-size: 0.875rem;
    margin: 0;
  }
  .prompt-list {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }
  .prompt-list-item {
    border: 1px solid rgba(148, 163, 184, 0.35);
    background: rgba(30, 41, 59, 0.6);
    color: inherit;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 0.8rem;
    cursor: pointer;
  }
  .prompt-list-item.active {
    border-color: #93c5fd;
  }
  .prompt-field {
    display: grid;
    gap: 4px;
    font-size: 0.875rem;
  }
  .prompt-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .prompt-meta {
    font-size: 0.75rem;
  }
</style>
