const blockedDataMimes = new Set([
  'text/html',
  'application/xhtml+xml',
  'image/svg+xml',
  'application/javascript',
  'text/javascript',
])

export function openDataUrlPreview(dataUrl: string): void {
  const trimmed = dataUrl.trim()
  const match = /^data:([^;,]*)/i.exec(trimmed)
  const mime = (match?.[1] ?? '').toLowerCase()
  if (mime !== '' && blockedDataMimes.has(mime)) {
    throw new Error('この形式の添付はブラウザで開けません。保存してから開いてください。')
  }
  window.open(trimmed, '_blank', 'noopener,noreferrer')
}
