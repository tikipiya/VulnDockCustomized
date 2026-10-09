<script lang="ts">
  import App from './App.svelte'
  import AuthShell from './AuthShell.svelte'
</script>

<AuthShell>
  {#snippet children()}
    <App />
  {/snippet}
</AuthShell>
