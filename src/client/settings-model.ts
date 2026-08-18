export const SLIDER_MAX = 31 as const

/** Map persisted remember days into the finite slider domain. */
export function sliderFromDays(days: unknown): number {
  if (days === -1) return SLIDER_MAX
  return typeof days === 'number' && Number.isFinite(days) ? Math.max(0, Math.min(SLIDER_MAX - 1, days)) : 0
}

/** Map the slider's forever position back to the persisted marker. */
export function daysFromSlider(value: number): number {
  return value === SLIDER_MAX ? -1 : value
}

/** Human-readable label for one slider position. */
export function rememberLabel(value: number): string {
  if (value === 0) return '每次都输入密码'
  if (value === SLIDER_MAX) return '永远免密登录（仅本机）'
  return `${value} 天内免密登录（仅本机）`
}

/** Format a remembered-login expiry timestamp for the settings panel. */
export function expiryText(milliseconds: number): string {
  const date = new Date(milliseconds)
  if (Number.isNaN(date.getTime())) return ''
  const month = String(date.getMonth() + 1).padStart(2, '0')
  const day = String(date.getDate()).padStart(2, '0')
  const hour = String(date.getHours()).padStart(2, '0')
  const minute = String(date.getMinutes()).padStart(2, '0')
  return `${date.getFullYear()}-${month}-${day} ${hour}:${minute}`
}
