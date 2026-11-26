import { expect, mock, test } from 'claude-code/testing'

const PANE = {
  plugin: 'ai-activity',
  component: 'Pane',
  requestId: 'ai-activity',
  props: {
    title: 'AI activity',
    isFocused: false,
    bodyColumns: 80,
    placement: 'dock',
    scroll: { offset: 0, bodyRows: 30 },
    view: {},
  },
} as const

const TABLE =
  'Codex: 0 running, 0 done (last 60m)\nQuota Codex (prolite): read 4m ago\n  1% used  wk\nOllama: 1 loaded, 0 established connection(s)\nLedger: 0 entries today, newest 1h ago\nCopilot: 1 review running, 0 unread (3 open PRs checked)\n'

const pane = (id: string, isPlaced = true) => ({
  id,
  title: 'AI activity',
  isShown: true,
  isFocused: false,
  isPlaced,
})

const out = (stdout: string, exitCode = 0) => ({
  value: { exitCode, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false },
})

// The table command is the sh -c lookup; the probe is the lookup alone.
const isTable = (argv: readonly string[]) => argv.join(' ').includes('--table')

test('the timer runs safo-activity in table mode through the path lookup and the pane shows it', async ($, on) => {
  const clock = mock.clock(on)
  const calls: Array<readonly string[]> = []
  on('command.register', () => ({ value: { command: 'ai' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.panes', () => ({ value: [pane('ai-activity')] }))
  on('process.run', (_, e) => {
    calls.push(e.argv)

    return out(isTable(e.argv) ? TABLE : '')
  })
  on('session.start', (_, e) => ({ cwd: e.cwd }))

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await clock.advance(2000)

  const table = calls.find(isTable)
  expect(table).toEqual([
    'sh',
    '-c',
    'command -v safo-activity >/dev/null 2>&1 && exec safo-activity --table || exit 0',
  ])
  // No absolute path to a script anywhere.
  expect(calls.every(argv => !argv.some(part => part.startsWith('/home/')))).toBe(true)

  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ ...PANE, surface })
    expect((await ui.find({ type: 'Text', text: /Codex:/ }))?.text).toMatch(/^Codex:/)
    expect((await ui.find({ type: 'Text', text: /Quota Codex/ }))?.text).toMatch(/^Quota Codex/)
    expect((await ui.find({ type: 'Text', text: /Ledger:/ }))?.text).toMatch(/^Ledger:/)
    expect((await ui.find({ type: 'Text', text: /Copilot:/ }))?.text).toMatch(/^Copilot:/)
    await ui.unmount()
  }
})

test('a failing command shows one short line', async ($, on) => {
  const clock = mock.clock(on)
  on('command.register', () => ({ value: { command: 'ai' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.panes', () => ({ value: [pane('ai-activity')] }))
  on('process.run', (_, e) => (isTable(e.argv) ? out('', 1) : out('')))
  on('session.start', (_, e) => ({ cwd: e.cwd }))

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await clock.advance(2000)

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect((await ui.find({ type: 'Text' }))?.text).toBe('safo-activity unavailable')
  await ui.unmount()
})

test('empty output draws nothing', async ($, on) => {
  const clock = mock.clock(on)
  on('command.register', () => ({ value: { command: 'ai' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.panes', () => ({ value: [pane('ai-activity')] }))
  on('process.run', () => out(''))
  on('session.start', (_, e) => ({ cwd: e.cwd }))

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await clock.advance(2000)

  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  expect(await ui.find({ type: 'Text' })).toBeUndefined()
  await ui.unmount()
})

test('without safo-activity the pane is not opened at session start and /ai says so', async ($, on) => {
  let opened = 0
  on('command.register', () => ({ value: { command: 'ai' } }))
  on('ui.open', () => {
    opened += 1

    return { value: { isPlaced: true } }
  })
  on('ui.panes', () => ({ value: [] }))
  on('process.run', () => out('', 1))
  on('session.start', (_, e) => ({ cwd: e.cwd }))

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  expect(opened).toBe(0)

  const ran = await $.command.run({ command: 'ai' })
  expect(ran.text).toMatch(/safo-activity is not installed/)
  expect(opened).toBe(0)
})

test('never two refreshes at once', async ($, on) => {
  const clock = mock.clock(on)
  let started = 0
  on('command.register', () => ({ value: { command: 'ai' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.panes', () => ({ value: [pane('ai-activity')] }))
  on('process.run', async (_, e) => {
    if (!isTable(e.argv)) return out('')
    started += 1
    await clock.sleep(7000)

    return out(TABLE)
  })
  on('session.start', (_, e) => ({ cwd: e.cwd }))

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await clock.advance(6000)

  // One run is still in flight after three ticks: no second one started.
  expect(started).toBe(1)
})

test('refreshing stops once the pane is closed', async ($, on) => {
  const clock = mock.clock(on)
  let runs = 0
  let isOpen = true
  on('command.register', () => ({ value: { command: 'ai' } }))
  on('ui.open', () => ({ value: { isPlaced: true } }))
  on('ui.panes', () => ({ value: isOpen ? [pane('ai-activity')] : [] }))
  on('process.run', (_, e) => {
    if (isTable(e.argv)) runs += 1

    return out(isTable(e.argv) ? TABLE : '')
  })
  on('session.start', (_, e) => ({ cwd: e.cwd }))

  await $.session.start({ cwd: '/', surface: 'terminal', isInteractive: true })
  await clock.advance(4000)
  const before = runs
  // The person closes the pane: the next tick finds it gone and stops.
  isOpen = false
  await clock.advance(10000)

  expect(before).toBeGreaterThan(0)
  expect(runs).toBe(before)
})
