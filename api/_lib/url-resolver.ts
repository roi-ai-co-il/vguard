/**
 * Generic URL reachability resolver (2026-06-25).
 *
 * Before any security probe runs, find the *reachable* version of a site. The
 * scanner must never report "Scan failed" just because the first HTTPS-normalized
 * URL timed out — many real sites only answer on http://, on www, or on the apex.
 *
 * Domain-agnostic: it generates the standard protocol × www/apex candidate grid,
 * tries them in a sensible order (HTTPS-first unless the user typed http://),
 * follows redirects, classifies the outcome, and returns the best reachable
 * candidate plus full per-attempt metadata. Pure + injectable `fetchFn`/`now` so
 * the unit tests run fully offline.
 *
 * Reachability classes (see resolveReachableUrl):
 *   - scannable            → 2xx (final, after redirects) over HTTPS
 *   - http_only            → 2xx but the final URL is http:// (HTTPS unavailable)
 *   - reachable_but_blocked→ best candidate is 401/403/405, nothing better exists
 *   - (failure)            → every candidate failed; structured error code
 *
 * The caller (runScan) reuses the winning Response directly, and the existing
 * `tls-http` finding + `httpsActive=false` hard-cap handle the HTTP-only penalty.
 */
import type { ResolutionAttempt, ResolverErrorType } from '../../src/lib/scanner-types.js'

export type { ResolutionAttempt, ResolverErrorType }

export type ReachabilityClass = 'scannable' | 'http_only' | 'reachable_but_blocked'

export type ResolverFailureCode =
  | 'all_candidates_failed'
  | 'dns_error'
  | 'tcp_connect_timeout'
  | 'tls_error'
  | 'http_timeout'
  | 'too_many_redirects'
  | 'unknown_network_error'

export interface ResolverSuccess {
  ok: true
  userInputUrl: string
  normalizedHost: string
  resolvedScanUrl: string
  usedFallback: boolean
  httpDowngraded: boolean
  reachability: ReachabilityClass
  status: number
  finalUrl: string
  /** The winning response — body intact (only a clone was read for the sample). */
  response: Response
  attempts: ResolutionAttempt[]
}

export interface ResolverFailure {
  ok: false
  userInputUrl: string
  normalizedHost: string
  code: ResolverFailureCode
  message: string
  attempts: ResolutionAttempt[]
}

export type ResolverResult = ResolverSuccess | ResolverFailure

export interface ResolveOptions {
  /** Injectable fetch (tests). Defaults to global fetch. */
  fetchFn?: typeof fetch
  /** Per-candidate timeout. Default 6000ms. */
  perCandidateTimeoutMs?: number
  /** Whole-resolver budget so a broken target can't hang the scan. Default 25000ms. */
  globalBudgetMs?: number
  /** Redirect follow limit. Default 5. */
  maxRedirects?: number
  /** Injectable clock (tests). Defaults to Date.now. */
  now?: () => number
  /** Request headers (runScan passes the scanner's browser-faithful set). */
  headers?: Record<string, string>
}

const DEFAULT_HEADERS: Record<string, string> = {
  'User-Agent':
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
}

interface ParsedInput {
  hadProtocol: boolean
  protocol: 'http:' | 'https:'
  hostname: string
  port: string
  pathname: string
  search: string
}

function parseInput(userInputUrl: string): ParsedInput | null {
  const trimmed = (userInputUrl ?? '').trim()
  if (!trimmed) return null
  const hadProtocol = /^https?:\/\//i.test(trimmed)
  let u: URL
  try {
    u = new URL(hadProtocol ? trimmed : `https://${trimmed}`)
  } catch {
    return null
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  return {
    hadProtocol,
    protocol: u.protocol as 'http:' | 'https:',
    hostname: u.hostname,
    port: u.port,
    pathname: u.pathname,
    search: u.search,
  }
}

/** The same host the user typed + its www↔apex counterpart. */
function hostVariants(hostname: string): { same: string; counterpart: string } {
  const lower = hostname.toLowerCase()
  if (lower.startsWith('www.')) return { same: lower, counterpart: lower.slice(4) }
  return { same: lower, counterpart: `www.${lower}` }
}

export interface Candidate {
  url: string
  isExact: boolean
  protocol: string
  host: string
}

/**
 * Ordered, de-duplicated candidate grid. Ordering rules (spec §4):
 *   explicit http://  → http same, http counterpart, https same, https counterpart
 *   explicit https:// → https same, https counterpart, http same, http counterpart
 *   no protocol       → https same, https counterpart, http same, http counterpart
 * The exact user URL is always first.
 */
export function generateCandidates(userInputUrl: string): Candidate[] {
  const p = parseInput(userInputUrl)
  if (!p) return []
  const { same, counterpart } = hostVariants(p.hostname)
  const portSuffix = p.port ? `:${p.port}` : ''
  const path = p.pathname && p.pathname !== '' ? p.pathname : '/'
  const mk = (proto: string, host: string) => `${proto}//${host}${portSuffix}${path}${p.search}`

  let ordered: string[]
  if (p.hadProtocol && p.protocol === 'http:') {
    ordered = [mk('http:', same), mk('http:', counterpart), mk('https:', same), mk('https:', counterpart)]
  } else {
    // explicit https OR no protocol → HTTPS-first
    ordered = [mk('https:', same), mk('https:', counterpart), mk('http:', same), mk('http:', counterpart)]
  }
  const exactUrl = ordered[0]
  const seen = new Set<string>()
  const out: Candidate[] = []
  for (const url of ordered) {
    if (seen.has(url)) continue
    seen.add(url)
    const uu = new URL(url)
    out.push({ url, isExact: url === exactUrl, protocol: uu.protocol, host: uu.host })
  }
  return out
}

/** Map a thrown fetch error to a structured resolver error type. */
export function classifyNetworkError(e: unknown): ResolverErrorType {
  const err = e as { name?: string; message?: string; code?: string; cause?: { code?: string } }
  const name = err?.name ?? ''
  const message = err?.message ?? ''
  if (name === 'AbortError' || /\babort/i.test(message)) return 'http_timeout'
  const code = err?.cause?.code ?? err?.code ?? ''
  if (/ENOTFOUND|EAI_AGAIN|ENODATA|EAI_NONAME|EAI_FAIL/.test(code)) return 'dns_error'
  if (/ECONNREFUSED|ECONNRESET|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|EPIPE|ECONNABORTED/.test(code))
    return 'tcp_connect_timeout'
  if (
    /CERT|TLS|SSL|DEPTH_ZERO|SELF_SIGNED|UNABLE_TO_VERIFY|ERR_TLS|HANDSHAKE|ALPN/.test(code) ||
    /certificate|self.signed|tls|ssl|handshake/i.test(message)
  )
    return 'tls_error'
  return 'unknown_network_error'
}

/** Strip obvious secrets from the 200-char body sample before storing it. */
function redactSample(s: string): string {
  return s
    .replace(/eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g, '[redacted-jwt]')
    .replace(
      /\b(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{30,}|sk_live_[A-Za-z0-9]{12,}|xox[abp]-[A-Za-z0-9-]{10,})\b/g,
      '[redacted-key]',
    )
    .replace(/\b[A-Za-z0-9._%+-]+:[^@\s/]{4,}@/g, '[redacted-creds]@')
}

interface CandidateOutcome {
  status: number | null
  errorType: ResolverErrorType | null
  errorMessage: string | null
  redirectChain: string[]
  finalUrl: string
  contentType: string | null
  bodySample: string
  startedAt: number
  durationMs: number
  response: Response | null
}

async function fetchCandidate(
  startUrl: string,
  opts: Required<Pick<ResolveOptions, 'fetchFn' | 'perCandidateTimeoutMs' | 'maxRedirects' | 'headers' | 'now'>>,
): Promise<CandidateOutcome> {
  const { fetchFn, perCandidateTimeoutMs, maxRedirects, headers, now } = opts
  const startedAt = now()
  const redirectChain: string[] = []
  let current = startUrl
  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), perCandidateTimeoutMs)
      let resp: Response
      try {
        resp = await fetchFn(current, {
          method: 'GET',
          headers,
          redirect: 'manual',
          signal: controller.signal,
        })
      } finally {
        clearTimeout(timer)
      }
      const status = resp.status
      if (status >= 300 && status < 400) {
        const loc = resp.headers.get('location')
        if (!loc) {
          // 3xx with no Location header — treat the response itself as final.
          return finalize(resp, current, redirectChain, startedAt, now)
        }
        redirectChain.push(current)
        if (redirectChain.length > maxRedirects) {
          return {
            status: null,
            errorType: 'too_many_redirects',
            errorMessage: `Exceeded ${maxRedirects} redirects`,
            redirectChain,
            finalUrl: current,
            contentType: null,
            bodySample: '',
            startedAt,
            durationMs: now() - startedAt,
            response: null,
          }
        }
        current = new URL(loc, current).toString()
        continue
      }
      return await finalize(resp, current, redirectChain, startedAt, now)
    }
    return {
      status: null,
      errorType: 'too_many_redirects',
      errorMessage: `Exceeded ${maxRedirects} redirects`,
      redirectChain,
      finalUrl: current,
      contentType: null,
      bodySample: '',
      startedAt,
      durationMs: now() - startedAt,
      response: null,
    }
  } catch (e) {
    return {
      status: null,
      errorType: classifyNetworkError(e),
      errorMessage: e instanceof Error ? e.message.slice(0, 200) : 'network error',
      redirectChain,
      finalUrl: current,
      contentType: null,
      bodySample: '',
      startedAt,
      durationMs: now() - startedAt,
      response: null,
    }
  }
}

async function finalize(
  resp: Response,
  requestedUrl: string,
  redirectChain: string[],
  startedAt: number,
  now: () => number,
): Promise<CandidateOutcome> {
  const contentType = resp.headers.get('content-type')
  let bodySample = ''
  try {
    bodySample = redactSample((await resp.clone().text()).slice(0, 200))
  } catch {
    // body not readable (HEAD-like / streamed) — leave sample empty
  }
  return {
    status: resp.status,
    errorType: null,
    errorMessage: null,
    redirectChain,
    finalUrl: resp.url || requestedUrl,
    contentType,
    bodySample,
    startedAt,
    durationMs: now() - startedAt,
    response: resp,
  }
}

/** All candidates failed → most representative code (specific if unanimous). */
function aggregateFailureCode(attempts: ResolutionAttempt[]): ResolverFailureCode {
  const types = attempts.map((a) => a.errorType).filter((t): t is ResolverErrorType => !!t)
  if (types.length === 0) return 'all_candidates_failed'
  const uniq = [...new Set(types)]
  if (uniq.length === 1) return uniq[0] as ResolverFailureCode
  return 'all_candidates_failed'
}

function attemptFrom(candidate: Candidate, userInputUrl: string, o: CandidateOutcome): ResolutionAttempt {
  const u = new URL(candidate.url)
  return {
    userInputUrl,
    candidateUrl: candidate.url,
    startedAt: o.startedAt,
    durationMs: o.durationMs,
    protocol: candidate.protocol,
    hostname: u.hostname,
    port: u.port,
    statusCode: o.status,
    errorType: o.errorType,
    errorMessage: o.errorMessage,
    redirectChain: o.redirectChain,
    contentType: o.contentType,
    responseBodySample: o.bodySample,
    selected: false,
    selectionReason: null,
  }
}

/**
 * Resolve the best reachable URL for a user-entered site. Tries every reasonable
 * candidate before failing. Returns the winning response (body intact) or a
 * structured failure with every attempt recorded.
 */
export async function resolveReachableUrl(
  userInputUrl: string,
  opts: ResolveOptions = {},
): Promise<ResolverResult> {
  const fetchFn = opts.fetchFn ?? (globalThis.fetch as typeof fetch)
  const perCandidateTimeoutMs = opts.perCandidateTimeoutMs ?? 6000
  const globalBudgetMs = opts.globalBudgetMs ?? 25000
  const maxRedirects = opts.maxRedirects ?? 5
  const now = opts.now ?? Date.now
  const headers = opts.headers ?? DEFAULT_HEADERS

  const parsed = parseInput(userInputUrl)
  const normalizedHost = parsed ? parsed.hostname : ''
  const candidates = generateCandidates(userInputUrl)
  const attempts: ResolutionAttempt[] = []

  if (candidates.length === 0) {
    return {
      ok: false,
      userInputUrl,
      normalizedHost,
      code: 'all_candidates_failed',
      message: 'The URL could not be parsed into any testable candidate.',
      attempts,
    }
  }

  const startGlobal = now()
  // The host answered with a non-2xx HTTP response. We keep the best such
  // candidate so a reachable-but-not-scannable site (WAF 403/406/429/451, auth
  // 401/405, or a bare 404/5xx) is handed to runScan's existing WAF/stealth +
  // blocked_by_waf/blocked_by_target logic — NOT mis-reported as a dead site.
  let blockedIdx = -1
  let answeredIdx = -1
  let chosen: { status: number; response: Response; finalUrl: string } | null = null
  let answered: { status: number; response: Response; finalUrl: string } | null = null
  // WAF / auth codes that strongly mean "alive but restricted" (mirrors the
  // scanner's wafLikely set + auth codes). Preferred over a bare 404/5xx.
  const BLOCKED_CODES = new Set([401, 403, 405, 406, 429, 451])

  for (const cand of candidates) {
    if (now() - startGlobal > globalBudgetMs) break // global budget exhausted

    const outcome = await fetchCandidate(cand.url, {
      fetchFn,
      perCandidateTimeoutMs,
      maxRedirects,
      headers,
      now,
    })
    const attempt = attemptFrom(cand, userInputUrl, outcome)
    attempts.push(attempt)

    if (outcome.errorType || outcome.status == null || !outcome.response) continue

    const status = outcome.status
    // A — reachable & scannable: 2xx (final, after redirects).
    if (status >= 200 && status < 300) {
      const finalUrl = outcome.finalUrl
      const httpDowngraded = new URL(finalUrl).protocol === 'http:'
      attempt.selected = true
      attempt.selectionReason = httpDowngraded
        ? 'reachable over HTTP only — HTTPS unavailable/failed'
        : 'reachable over HTTPS'
      return {
        ok: true,
        userInputUrl,
        normalizedHost,
        resolvedScanUrl: finalUrl,
        usedFallback: !cand.isExact || finalUrl !== cand.url,
        httpDowngraded,
        reachability: httpDowngraded ? 'http_only' : 'scannable',
        status,
        finalUrl,
        response: outcome.response,
        attempts,
      }
    }
    // C — reachable but not scannable. Remember the best one but keep trying for
    // a genuinely scannable (2xx) candidate.
    if (!answered) {
      answered = { status, response: outcome.response, finalUrl: outcome.finalUrl }
      answeredIdx = attempts.length - 1
    }
    if (BLOCKED_CODES.has(status) && !chosen) {
      chosen = { status, response: outcome.response, finalUrl: outcome.finalUrl }
      blockedIdx = attempts.length - 1
    }
  }

  // No scannable candidate. Prefer a WAF/auth-coded response, else any answer.
  const pick = chosen ?? answered
  if (pick) {
    const pickIdx = chosen ? blockedIdx : answeredIdx
    attempts[pickIdx].selected = true
    attempts[pickIdx].selectionReason = `reachable but not scannable (HTTP ${pick.status}) — handed to WAF/4xx handling`
    return {
      ok: true,
      userInputUrl,
      normalizedHost,
      resolvedScanUrl: pick.finalUrl,
      usedFallback: true,
      httpDowngraded: new URL(pick.finalUrl).protocol === 'http:',
      reachability: 'reachable_but_blocked',
      status: pick.status,
      finalUrl: pick.finalUrl,
      response: pick.response,
      attempts,
    }
  }

  // D — unreachable after exhaustive resolution.
  const code = aggregateFailureCode(attempts)
  const tried = attempts.map((a) => a.candidateUrl).join(', ')
  return {
    ok: false,
    userInputUrl,
    normalizedHost,
    code,
    message: `We tried HTTPS, HTTP, www, and non-www versions, but the site did not respond (${code}). Attempted: ${tried}.`,
    attempts,
  }
}
