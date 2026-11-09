import { atom, read, update } from 'claude-code'
import type { Hook, Register } from 'claude-code'

type Dollar = Parameters<Hook<'session.start'>>[0]

const PANE = 'ai-activity'
const TITLE = 'AI activity'
// No shell logic beyond a path lookup: the same sh -c pattern as the SAFO hooks in settings. When safo-activity is
// not on the path the command exits 0 with no output and the pane draws nothing. safo-activity cleans every field it
// prints; this mod only displays it.
const TABLE = ['sh', '-c', 'command -v safo-activity >/dev/null 2>&1 && exec safo-activity --table || exit 0']
const PROBE = ['sh', '-c', 'command -v safo-activity >/dev/null 2>&1']
const UNAVAILABLE = 'safo-activity unavailable'
const NOT_INSTALLED = 'safo-activity is not installed (see docs/activity.md in the SAFO repository).'
const EVERY_MS = 2000

// Change the tag if the stored text changes shape.
const view = atom({ plugin: 'ai-activity', key: 'text' } as const, '', {
  shape: 'text-1',
})

// Colours for the provider headers (plain Text props only). Bold uses the `bold` prop, the older spelling that every
// Claude Code with mods accepts; newer versions deprecate it in favour of `weight` but still draw it.
const HEADERS: Array<[string, string]> = [
  ['Codex:', 'cyan'],
  ['Quota ', 'magenta'],
  ['Ollama:', 'green'],
  ['Ledger:', 'yellow'],
  ['Copilot:', 'blue'],
]

// Module variables start over on a reload, which also drops the timer.
const run: {
  timer: { cancel: () => void } | undefined
  isBusy: boolean
  last: string | undefined
} = { timer: undefined, isBusy: false, last: undefined }

function stop(): void {
  run.timer?.cancel()
  run.timer = undefined
}

// True only when safo-activity is on the path.
async function isInstalled($: Dollar): Promise<boolean> {
  try {
    const ran = await $.process.run(PROBE, { timeoutMs: 3000 })

    return ran.exitCode === 0
  } catch {
    return false
  }
}

// One refresh at a time; writes nothing but the pane's own state.
async function refresh($: Dollar): Promise<void> {
  if (run.isBusy) return
  run.isBusy = true
  try {
    const isOpen = (await $.ui.panes()).some(pane => pane.id === PANE)
    if (!isOpen) {
      stop()

      return
    }
    let text = UNAVAILABLE
    try {
      const ran = await $.process.run(TABLE, { timeoutMs: 8000 })
      // Empty output (the tool is missing, or there is nothing to say) draws nothing.
      if (ran.exitCode === 0) text = ran.stdout.trim() === '' ? '' : ran.stdout
    } catch {
      text = UNAVAILABLE
    }
    if (text !== run.last) {
      run.last = text
      await update($, view, () => text)
    }
  } finally {
    run.isBusy = false
  }
}

function start($: Dollar): void {
  if (run.timer === undefined) {
    run.timer = $.clock.every(EVERY_MS, () => {
      void refresh($)
    })
  }
  void refresh($)
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'ai',
      description: 'Show or hide the AI activity pane (Codex, quota, Ollama, ledger, Copilot)',
    })
    // Not opened when the tool is missing. Asked of nobody: it seats from 144 columns and waits below that.
    if (await isInstalled($)) {
      await $.ui.open({ id: PANE, title: TITLE })
      start($)
    }

    return next(e)
  })

  on('command.run', { command: 'ai' }, async $ => {
    const isUp = (await $.ui.panes()).some(pane => pane.id === PANE)
    if (isUp) {
      await $.ui.close({ id: PANE })
      stop()

      return { text: 'AI activity pane closed.' }
    }
    if (!(await isInstalled($))) return { text: NOT_INSTALLED }
    await $.ui.open({ id: PANE, title: TITLE })
    start($)

    return { text: 'AI activity pane opened.' }
  })

  // Stop refreshing when the pane closes, by whoever closes it.
  on('ui.close', async ($, e, next) => {
    const closed = await next(e)
    if (e.id === PANE) stop()

    return closed
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const text = await read($, view)
    const lines = text === '' ? [] : text.split('\n')
    const room = Math.max(1, (e.viewport?.rows ?? 40) - 3)

    return (
      <Box flexDirection="column">
        {lines.slice(0, room).map(line => {
          const header = HEADERS.find(([prefix]) => line.startsWith(prefix))
          if (header !== undefined) {
            return (
              <Text color={header[1]} bold>
                {line}
              </Text>
            )
          }
          const isNote = line.trimStart().startsWith('note:')

          return <Text dimColor={isNote}>{line}</Text>
        })}
      </Box>
    )
  })
}
