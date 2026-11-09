export type AiActivityText = string

// One Claude rate-limit window as drawn: label (5h, wk or the raw kind),
// percent used (0 to 100), and the time left to the reset ('' when unknown).
export type AiActivityQuotaRow = { label: string; percent: number; left: string }

declare module 'claude-code' {
  interface PluginState {
    'ai-activity': {
      text: Shaped<AiActivityText>
      quota: Shaped<AiActivityQuotaRow[]>
    }
  }
}
