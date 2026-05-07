#!/usr/bin/env node
/**
 * Vguard CLI — `npx vguard scan <url>`
 *
 * Thin Node wrapper around the production Vguard API. Streams progress as
 * the scan runs, then prints a colored findings table. Designed for:
 *   - Developers who'd rather stay in the terminal than open a browser
 *   - CI pipelines that want to gate merges on findings (--exit-code)
 *   - Agents (Claude Code / Cursor / Cline) that can run shell commands
 *     and consume JSON (--json)
 *
 * No dependencies — uses native fetch + node:tty for color detection.
 */

const API_BASE = process.env.VGUARD_API ?? 'https://v-guards.com'

type Severity = 'critical' | 'warn' | 'info' | 'ok'

interface Finding {
  id: string
  severity: Severity
  category: string
  title: string
  description: string
  evidence: string
  fixPrompt: string
}

interface ScanError {
  code: string
  message: string
  httpStatus?: number
  wafVendor?: string
  suggestedAction?: string
}

interface ScanResult {
  ok: true
  url: string
  vibeScore: number
  totals: { critical: number; warn: number; info: number; ok: number }
  findings: Finding[]
  meta: { finalUrl: string; detectedFramework: string | null }
  attackSurface?: {
    wafVendor?: string | null
    wafBlocked?: boolean
    stealthRetrySucceeded?: boolean
  }
}

interface ScanFailure {
  ok: false
  error: ScanError
}

type ScanResponse = ScanResult | ScanFailure

interface PhaseEvent {
  type: 'phase'
  step: number
  total: number
  name: string
  label: string
}

interface ResultEvent {
  type: 'result'
  result: ScanResponse
}

type StreamEvent = PhaseEvent | ResultEvent

const supportsColor = process.stdout.isTTY && process.env.NO_COLOR !== '1'
const c = {
  reset: supportsColor ? '\x1b[0m' : '',
  dim: supportsColor ? '\x1b[2m' : '',
  bold: supportsColor ? '\x1b[1m' : '',
  red: supportsColor ? '\x1b[31m' : '',
  yellow: supportsColor ? '\x1b[33m' : '',
  cyan: supportsColor ? '\x1b[36m' : '',
  green: supportsColor ? '\x1b[32m' : '',
  blue: supportsColor ? '\x1b[34m' : '',
  gray: supportsColor ? '\x1b[90m' : '',
}

function severityColor(sev: Severity): string {
  if (sev === 'critical') return c.red
  if (sev === 'warn') return c.yellow
  if (sev === 'info') return c.blue
  return c.green
}

function severityIcon(sev: Severity): string {
  if (sev === 'critical') return '✖'
  if (sev === 'warn') return '⚠'
  if (sev === 'info') return 'ℹ'
  return '✔'
}

function gradeColor(score: number): string {
  if (score >= 90) return c.green
  if (score >= 75) return c.cyan
  if (score >= 60) return c.yellow
  return c.red
}

function gradeLetter(score: number): string {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

interface Args {
  command: 'scan' | 'help' | 'version'
  url?: string
  json: boolean
  exitCode: boolean
  prompt: boolean
  showFindingId?: string
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    command: 'help',
    json: false,
    exitCode: false,
    prompt: false,
  }
  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help' || argv[0] === 'help') {
    args.command = 'help'
    return args
  }
  if (argv[0] === '-v' || argv[0] === '--version' || argv[0] === 'version') {
    args.command = 'version'
    return args
  }
  if (argv[0] === 'scan') {
    args.command = 'scan'
    for (let i = 1; i < argv.length; i++) {
      const a = argv[i]
      if (a === '--json') args.json = true
      else if (a === '--exit-code') args.exitCode = true
      else if (a === '--prompt') args.prompt = true
      else if (a.startsWith('--prompt=')) {
        args.prompt = true
        args.showFindingId = a.slice('--prompt='.length)
      } else if (!a.startsWith('-') && !args.url) {
        args.url = a
      }
    }
    return args
  }
  // First arg is a URL — shorthand for `vguard scan <url>`
  if (/^https?:\/\//.test(argv[0])) {
    args.command = 'scan'
    args.url = argv[0]
    for (let i = 1; i < argv.length; i++) {
      const a = argv[i]
      if (a === '--json') args.json = true
      else if (a === '--exit-code') args.exitCode = true
      else if (a === '--prompt') args.prompt = true
    }
    return args
  }
  args.command = 'help'
  return args
}

function printHelp(): void {
  process.stdout.write(`
${c.bold}vguard${c.reset} ${c.dim}— security scanner for vibe-coded apps${c.reset}

${c.bold}Usage:${c.reset}
  npx vguard scan <url> [options]
  npx vguard <url>                ${c.dim}(shorthand)${c.reset}

${c.bold}Options:${c.reset}
  --json          Output the raw ScanResponse as JSON (machine-readable)
  --exit-code     Exit 1 if any critical/warn findings (use in CI)
  --prompt        Print the full fix prompt for every finding
  --prompt=<id>   Print the fix prompt for a specific finding only

${c.bold}Examples:${c.reset}
  npx vguard scan https://your-app.vercel.app
  npx vguard https://example.com --json
  npx vguard scan https://app.example.com --exit-code   ${c.dim}# CI gate${c.reset}

${c.bold}Environment:${c.reset}
  VGUARD_API=<url>   Override API base (default: https://v-guards.com)
  NO_COLOR=1         Disable ANSI color output

${c.bold}Web UI:${c.reset}  https://v-guards.com
${c.bold}Docs:${c.reset}    https://v-guards.com
`)
}

async function streamScan(
  url: string,
  onPhase: (e: PhaseEvent) => void,
): Promise<ScanResponse> {
  const resp = await fetch(`${API_BASE}/api/scan-stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  if (!resp.ok || !resp.body) {
    throw new Error(`HTTP ${resp.status} from ${API_BASE}/api/scan-stream`)
  }
  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let result: ScanResponse | null = null
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      const t = line.trim()
      if (!t) continue
      try {
        const ev = JSON.parse(t) as StreamEvent
        if (ev.type === 'phase') onPhase(ev)
        else if (ev.type === 'result') result = ev.result
      } catch {
        // skip malformed lines
      }
    }
  }
  if (buffer.trim()) {
    try {
      const ev = JSON.parse(buffer.trim()) as StreamEvent
      if (ev.type === 'result') result = ev.result
    } catch {
      // ignore trailing partial
    }
  }
  if (!result) throw new Error('Stream closed without a result event')
  return result
}

function renderProgress(phase: PhaseEvent): void {
  // Replace the current line each phase tick.
  if (process.stdout.isTTY) {
    process.stdout.write(
      `\r${c.cyan}⏵${c.reset} ${c.dim}[${phase.step}/${phase.total}]${c.reset} ${phase.label}${' '.repeat(40)}`,
    )
  } else {
    process.stdout.write(`[${phase.step}/${phase.total}] ${phase.label}\n`)
  }
}

function clearProgressLine(): void {
  if (process.stdout.isTTY) {
    process.stdout.write(`\r${' '.repeat(80)}\r`)
  }
}

function renderResult(result: ScanResult): void {
  const grade = gradeLetter(result.vibeScore)
  const gc = gradeColor(result.vibeScore)
  process.stdout.write(`\n${c.bold}Vibe Score:${c.reset} ${gc}${c.bold}${result.vibeScore}/100${c.reset} ${gc}(${grade})${c.reset}\n`)
  process.stdout.write(`${c.dim}URL:${c.reset} ${result.meta.finalUrl}\n`)
  if (result.meta.detectedFramework) {
    process.stdout.write(`${c.dim}Stack:${c.reset} ${result.meta.detectedFramework}\n`)
  }
  if (result.attackSurface?.wafVendor) {
    const note = result.attackSurface.wafBlocked
      ? result.attackSurface.stealthRetrySucceeded
        ? '(initial blocked, stealth retry succeeded)'
        : '(blocked)'
      : ''
    process.stdout.write(`${c.dim}Edge:${c.reset} ${c.yellow}${result.attackSurface.wafVendor}${c.reset} ${c.dim}${note}${c.reset}\n`)
  }
  process.stdout.write(
    `${c.dim}Totals:${c.reset} ${c.red}${result.totals.critical} critical${c.reset}  ${c.yellow}${result.totals.warn} warn${c.reset}  ${c.blue}${result.totals.info} info${c.reset}  ${c.green}${result.totals.ok} ok${c.reset}\n\n`,
  )

  if (result.findings.length === 0) {
    process.stdout.write(`${c.green}No findings — clean scan.${c.reset}\n`)
    return
  }

  // Print one-line-per-finding, sorted critical → warn → info → ok.
  const order: Record<Severity, number> = { critical: 0, warn: 1, info: 2, ok: 3 }
  const sorted = [...result.findings].sort((a, b) => order[a.severity] - order[b.severity])
  for (const f of sorted) {
    const sc = severityColor(f.severity)
    const ic = severityIcon(f.severity)
    process.stdout.write(`  ${sc}${ic} ${f.severity.padEnd(8)}${c.reset} ${c.dim}${f.category.padEnd(14)}${c.reset} ${f.title}\n`)
    process.stdout.write(`    ${c.dim}${f.id}${c.reset}\n`)
  }
  process.stdout.write(
    `\n${c.dim}Use ${c.reset}--prompt=<id>${c.dim} to print the full fix prompt for a specific finding.${c.reset}\n`,
  )
  process.stdout.write(`${c.dim}Web report: ${API_BASE}/?url=${encodeURIComponent(result.meta.finalUrl)}${c.reset}\n`)
}

function renderFailure(err: ScanError, target: string): void {
  if (err.code === 'blocked_by_waf') {
    process.stdout.write(
      `\n${c.yellow}${c.bold}Target denied automated access${c.reset}\n` +
        `${c.dim}This isn't a Vguard failure — ${target}'s edge protection blocked the scan from our IP.${c.reset}\n`,
    )
    if (err.wafVendor) {
      process.stdout.write(`${c.dim}Vendor:${c.reset} ${c.yellow}${err.wafVendor}${c.reset}\n`)
    }
    if (err.httpStatus) {
      process.stdout.write(`${c.dim}HTTP status:${c.reset} ${err.httpStatus}\n`)
    }
    process.stdout.write(
      `\n${c.cyan}Run Stage 2 from your browser instead:${c.reset} ${API_BASE}/?url=${encodeURIComponent(target)}\n`,
    )
    return
  }
  process.stdout.write(
    `\n${c.red}${c.bold}Scan failed${c.reset} ${c.dim}(${err.code})${c.reset}\n${err.message}\n`,
  )
}

async function runScanCommand(args: Args): Promise<number> {
  if (!args.url) {
    process.stderr.write(`${c.red}Error:${c.reset} URL is required.\n\nRun ${c.bold}vguard --help${c.reset} for usage.\n`)
    return 2
  }

  if (!args.json) {
    process.stdout.write(`${c.cyan}Vguard${c.reset} ${c.dim}scanning${c.reset} ${args.url}\n`)
  }

  let response: ScanResponse
  try {
    response = await streamScan(args.url, (phase) => {
      if (!args.json) renderProgress(phase)
    })
    if (!args.json) clearProgressLine()
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : 'unknown error'
    if (args.json) {
      process.stdout.write(JSON.stringify({ ok: false, error: { code: 'cli_error', message: msg } }) + '\n')
    } else {
      process.stderr.write(`\n${c.red}Network error:${c.reset} ${msg}\n`)
    }
    return 1
  }

  if (args.json) {
    process.stdout.write(JSON.stringify(response, null, 2) + '\n')
  } else if (!response.ok) {
    renderFailure(response.error, args.url)
  } else {
    renderResult(response)
    if (args.prompt) {
      printPrompts(response, args.showFindingId)
    }
  }

  if (args.exitCode) {
    if (!response.ok) return 2
    if (response.totals.critical > 0) return 1
    if (response.totals.warn > 0) return 1
    return 0
  }
  return 0
}

function printPrompts(result: ScanResult, onlyId?: string): void {
  const targets = onlyId
    ? result.findings.filter((f) => f.id === onlyId)
    : result.findings.filter((f) => f.severity !== 'ok')
  if (targets.length === 0) {
    if (onlyId) {
      process.stdout.write(`\n${c.yellow}No finding with id "${onlyId}".${c.reset}\n`)
    }
    return
  }
  for (const f of targets) {
    process.stdout.write(`\n${c.dim}${'─'.repeat(70)}${c.reset}\n${c.bold}${f.id}${c.reset}\n${c.dim}${'─'.repeat(70)}${c.reset}\n${f.fixPrompt}\n`)
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2))
  if (args.command === 'help') {
    printHelp()
    process.exit(0)
  }
  if (args.command === 'version') {
    // Read version from package.json at runtime via import-meta. Hardcode to
    // avoid an extra fs read; bumped in lockstep with package.json.
    process.stdout.write('vguard 0.1.0\n')
    process.exit(0)
  }
  const code = await runScanCommand(args)
  process.exit(code)
}

main().catch((e) => {
  process.stderr.write(`${c.red}Unexpected error:${c.reset} ${e instanceof Error ? e.message : String(e)}\n`)
  process.exit(1)
})
