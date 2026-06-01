#!/usr/bin/env node
// @ts-check
/**
 * Vguard GitHub Action — runs a scan against the input URL, writes outputs,
 * and (optionally) posts/updates a PR comment with the findings table.
 *
 * No npm dependencies. All HTTP calls use native fetch; PR commenting uses
 * the GITHUB_TOKEN that GitHub Actions provides automatically.
 *
 * Inputs/outputs are documented in action.yml. Environment vars provided by
 * the GitHub Actions runtime:
 *   GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH, GITHUB_OUTPUT,
 *   GITHUB_STEP_SUMMARY, INPUT_<NAME-IN-CAPS>
 */

import { readFileSync, appendFileSync } from 'node:fs'

const SEV_ORDER = { critical: 0, warn: 1, info: 2, ok: 3 }

function getInput(name, fallback = '') {
  const v = process.env[`INPUT_${name.toUpperCase().replace(/-/g, '_')}`]
  return (v === undefined || v === '' ? fallback : v).trim()
}

function setOutput(name, value) {
  const out = process.env.GITHUB_OUTPUT
  if (!out) return
  appendFileSync(out, `${name}=${String(value).replace(/\n/g, '%0A')}\n`)
}

function appendStepSummary(md) {
  const path = process.env.GITHUB_STEP_SUMMARY
  if (!path) return
  appendFileSync(path, md + '\n')
}

function fail(msg, code = 1) {
  process.stderr.write(`::error::${msg}\n`)
  process.exit(code)
}

function severityIcon(sev) {
  return sev === 'critical' ? '🔴' : sev === 'warn' ? '🟡' : sev === 'info' ? '🔵' : '🟢'
}

function gradeColor(score) {
  if (score >= 90) return '🟢'
  if (score >= 75) return '🟢'
  if (score >= 60) return '🟡'
  if (score >= 40) return '🟠'
  return '🔴'
}

function gradeLetter(score) {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

async function streamScan(apiBase, url) {
  const resp = await fetch(`${apiBase}/api/scan-stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
  if (!resp.ok || !resp.body) throw new Error(`HTTP ${resp.status} from /api/scan-stream`)
  const reader = resp.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  let result = null
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
        const ev = JSON.parse(t)
        if (ev.type === 'phase') {
          process.stdout.write(`[${ev.step}/${ev.total}] ${ev.label}\n`)
        } else if (ev.type === 'result') {
          result = ev.result
        }
      } catch {
        // skip malformed
      }
    }
  }
  if (buffer.trim()) {
    try {
      const ev = JSON.parse(buffer.trim())
      if (ev.type === 'result') result = ev.result
    } catch {
      // ignore trailing partial
    }
  }
  if (!result) throw new Error('Stream closed without a result event')
  return result
}

function buildCommentBody(scanned, response, tag) {
  const marker = `<!-- ${tag}-comment-marker -->`
  const lines = [marker, '', '## 🛡️ Vguard security scan']
  if (!response.ok) {
    const e = response.error
    if (e.code === 'blocked_by_waf') {
      lines.push('')
      lines.push(`> **Target denied automated access** — \`${scanned}\` returned **HTTP ${e.httpStatus ?? '4xx'}**${e.wafVendor ? ` (\`${e.wafVendor}\`)` : ''}.`)
      lines.push(
        '> The WAF in front of the origin blocked our IP. Real users are unaffected. ' +
          '[Run Stage 2 from your browser instead](' + scanned + ').',
      )
    } else {
      lines.push('')
      lines.push(`> **Scan failed** — \`${e.code}\`: ${e.message}`)
    }
    return lines.join('\n')
  }
  const r = response
  lines.push('')
  lines.push(`**Score:** ${gradeColor(r.vibeScore)} **${r.vibeScore}/100** (grade ${gradeLetter(r.vibeScore)})`)
  lines.push(`**URL:** \`${r.meta.finalUrl}\``)
  if (r.meta.detectedFramework) lines.push(`**Stack:** ${r.meta.detectedFramework}`)
  lines.push(
    `**Totals:** 🔴 ${r.totals.critical} critical · 🟡 ${r.totals.warn} warn · 🔵 ${r.totals.info} info · 🟢 ${r.totals.ok} ok`,
  )
  if (r.attackSurface?.wafVendor) {
    const note = r.attackSurface.wafBlocked
      ? r.attackSurface.stealthRetrySucceeded
        ? '_(initial blocked; stealth retry succeeded)_'
        : '_(blocked)_'
      : ''
    lines.push(`**Edge:** ${r.attackSurface.wafVendor} ${note}`)
  }
  lines.push('')

  const sorted = [...r.findings].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity])
  const actionable = sorted.filter((f) => f.severity !== 'ok')
  if (actionable.length === 0) {
    lines.push('🟢 **No actionable findings.** Nothing to fix.')
    return lines.join('\n')
  }

  lines.push('| Severity | Category | Title | ID |')
  lines.push('|---|---|---|---|')
  for (const f of actionable.slice(0, 50)) {
    lines.push(`| ${severityIcon(f.severity)} ${f.severity} | \`${f.category}\` | ${f.title.replace(/\|/g, '\\|')} | \`${f.id}\` |`)
  }
  if (actionable.length > 50) {
    lines.push('')
    lines.push(`_…and ${actionable.length - 50} more. View the full report at the URL below._`)
  }

  lines.push('')
  lines.push(
    `<details><summary>How to run a fix prompt</summary>` +
      `\n\nEvery finding ships with a paste-ready prompt for Cursor / Claude Code / Cline. From your terminal:\n\n` +
      '```bash\n' +
      `npx vguard scan ${r.meta.finalUrl} --prompt=<finding-id>\n` +
      '```\n' +
      '</details>',
  )
  lines.push('')
  lines.push(`[View the full report on Vguard →](${process.env.INPUT_API_URL || 'https://v-guards.com'}/?url=${encodeURIComponent(r.meta.finalUrl)})`)
  return lines.join('\n')
}

async function findExistingComment(repo, prNumber, tag, token) {
  const marker = `<!-- ${tag}-comment-marker -->`
  let page = 1
  while (page < 10) {
    const resp = await fetch(
      `https://api.github.com/repos/${repo}/issues/${prNumber}/comments?per_page=100&page=${page}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      },
    )
    if (!resp.ok) throw new Error(`GitHub API ${resp.status}: ${await resp.text().catch(() => '')}`)
    const list = /** @type {{ id: number; body: string }[]} */ (await resp.json())
    if (list.length === 0) return null
    const found = list.find((c) => typeof c.body === 'string' && c.body.includes(marker))
    if (found) return found.id
    if (list.length < 100) return null
    page++
  }
  return null
}

async function upsertComment(repo, prNumber, body, tag, token) {
  const existing = await findExistingComment(repo, prNumber, tag, token)
  if (existing) {
    const resp = await fetch(`https://api.github.com/repos/${repo}/issues/comments/${existing}`, {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ body }),
    })
    if (!resp.ok) throw new Error(`PATCH comment ${resp.status}`)
    return
  }
  const resp = await fetch(`https://api.github.com/repos/${repo}/issues/${prNumber}/comments`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ body }),
  })
  if (!resp.ok) throw new Error(`POST comment ${resp.status}`)
}

function getPrNumberFromEvent() {
  const path = process.env.GITHUB_EVENT_PATH
  if (!path) return null
  try {
    const event = JSON.parse(readFileSync(path, 'utf8'))
    return event?.pull_request?.number ?? event?.issue?.number ?? null
  } catch {
    return null
  }
}

// --- Auto-fix PR -----------------------------------------------------------

async function gh(method, path, token, body) {
  const resp = await fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'vguard-action',
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  })
  return resp
}

/**
 * Build VGUARD_FIXES.md — a paste-ready remediation playbook. Vguard scans the
 * live URL (not the repo), so we can't auto-edit source; instead we hand the dev
 * (or their AI agent) one PR where every finding is a ready-to-paste fix prompt.
 */
function buildFixesMarkdown(url, response) {
  const lines = []
  lines.push(`# 🛡 Vguard — security fixes for \`${url}\``)
  lines.push('')
  if (response.ok) {
    lines.push(`**Vibe Score:** ${response.vibeScore}/100 (${gradeLetter(response.vibeScore)})`)
  }
  lines.push('')
  lines.push('> Hand this file to your AI coding agent (Cursor / Claude / Lovable / Bolt). Each section below is a ready-to-paste fix prompt for one finding. Work top-down — critical first.')
  lines.push('')
  const actionable = (response.findings || []).filter(
    (f) => f.fixPrompt && f.severity && f.severity !== 'ok',
  )
  const order = { critical: 0, warn: 1, info: 2 }
  actionable.sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3))
  actionable.forEach((f, i) => {
    lines.push(`## ${i + 1}. ${severityIcon(f.severity)} ${f.title || f.id}`)
    if (f.description) lines.push('', f.description)
    if (f.evidence) {
      lines.push('', '**Evidence:**', '```', String(f.evidence).slice(0, 1000), '```')
    }
    lines.push('', '**Fix prompt — paste into your AI agent:**', '', '```text', f.fixPrompt, '```', '')
  })
  if (!actionable.length) lines.push('No actionable findings — clean scan. ✅')
  lines.push('', '---', `_Generated by [Vguard](https://v-guards.com) · ${new Date().toISOString()}_`)
  return lines.join('\n')
}

/** Open (or update) a single fixes PR via the REST API. Returns the PR URL or null. */
async function createFixPr(repo, token, branch, url, response) {
  const actionable = (response.ok ? response.findings || [] : []).filter(
    (f) => f.fixPrompt && f.severity && f.severity !== 'ok',
  )
  if (!actionable.length) {
    process.stdout.write('No actionable findings — skipping fixes PR.\n')
    return null
  }

  // 1. default branch + its head sha
  const repoResp = await gh('GET', `/repos/${repo}`, token)
  if (!repoResp.ok) throw new Error(`GET repo ${repoResp.status}`)
  const base = (await repoResp.json()).default_branch
  const refResp = await gh('GET', `/repos/${repo}/git/ref/heads/${encodeURIComponent(base)}`, token)
  if (!refResp.ok) throw new Error(`GET base ref ${refResp.status}`)
  const baseSha = (await refResp.json()).object.sha

  // 2. ensure the fixes branch exists (create from base head if missing)
  const branchRef = `heads/${branch}`
  const existingBranch = await gh('GET', `/repos/${repo}/git/ref/${branchRef}`, token)
  if (existingBranch.status === 404) {
    const create = await gh('POST', `/repos/${repo}/git/refs`, token, {
      ref: `refs/heads/${branch}`,
      sha: baseSha,
    })
    if (!create.ok) throw new Error(`create branch ${create.status}`)
  }

  // 3. commit VGUARD_FIXES.md on the branch (update if it already exists)
  const content = Buffer.from(buildFixesMarkdown(url, response), 'utf8').toString('base64')
  let existingFileSha
  const fileResp = await gh(
    'GET',
    `/repos/${repo}/contents/VGUARD_FIXES.md?ref=${encodeURIComponent(branch)}`,
    token,
  )
  if (fileResp.ok) existingFileSha = (await fileResp.json()).sha
  const put = await gh('PUT', `/repos/${repo}/contents/VGUARD_FIXES.md`, token, {
    message: `chore(security): Vguard fixes for ${url}`,
    content,
    branch,
    ...(existingFileSha ? { sha: existingFileSha } : {}),
  })
  if (!put.ok) throw new Error(`commit fixes file ${put.status}`)

  // 4. find-or-create the PR
  const owner = repo.split('/')[0]
  const open = await gh(
    'GET',
    `/repos/${repo}/pulls?state=open&head=${encodeURIComponent(`${owner}:${branch}`)}`,
    token,
  )
  const openList = open.ok ? await open.json() : []
  if (openList.length) return openList[0].html_url
  const critical = actionable.filter((f) => f.severity === 'critical').length
  const pr = await gh('POST', `/repos/${repo}/pulls`, token, {
    title: `🛡 Vguard security fixes${critical ? ` (${critical} critical)` : ''}`,
    head: branch,
    base,
    body: `Vguard scanned \`${url}\` and found ${actionable.length} actionable issue(s). This PR adds **VGUARD_FIXES.md** with a paste-ready AI fix prompt for each one — hand it to your coding agent, then close this PR once resolved.\n\n_Re-running the action updates this PR in place._`,
  })
  if (!pr.ok) throw new Error(`open PR ${pr.status}`)
  return (await pr.json()).html_url
}

async function main() {
  const url = getInput('url')
  if (!url) fail('Input "url" is required.')

  const failOn = getInput('fail-on', 'warn').toLowerCase()
  const commentOnPr = getInput('comment-on-pr', 'true').toLowerCase() !== 'false'
  const tag = getInput('comment-tag', 'vguard')
  const apiBase = getInput('api-url', 'https://v-guards.com')
  const createPr = getInput('create-fix-pr', 'false').toLowerCase() === 'true'
  const fixBranch = getInput('fix-pr-branch', 'vguard/security-fixes')

  process.stdout.write(`Scanning ${url}\n`)

  /** @type {any} */
  let response
  try {
    response = await streamScan(apiBase, url)
  } catch (e) {
    fail(`Network error during scan: ${e instanceof Error ? e.message : String(e)}`)
    return
  }

  if (!response.ok) {
    setOutput('outcome', response.error.code)
    process.stderr.write(`::warning::Vguard scan returned ${response.error.code}: ${response.error.message}\n`)
  } else {
    setOutput('outcome', 'success')
    setOutput('vibe-score', response.vibeScore)
    setOutput('critical', response.totals.critical)
    setOutput('warn', response.totals.warn)
    setOutput('info', response.totals.info)
  }

  const body = buildCommentBody(url, response, tag)
  appendStepSummary(body)

  const prNumber = getPrNumberFromEvent()
  const repo = process.env.GITHUB_REPOSITORY
  const token = process.env.GITHUB_TOKEN
  if (commentOnPr && prNumber && repo && token) {
    try {
      await upsertComment(repo, prNumber, body, tag, token)
      process.stdout.write(`Posted/updated PR comment on #${prNumber}\n`)
    } catch (e) {
      process.stderr.write(`::warning::Could not post PR comment: ${e instanceof Error ? e.message : String(e)}\n`)
    }
  } else if (commentOnPr) {
    process.stdout.write('Skipping PR comment (not a PR event, or missing GITHUB_TOKEN).\n')
  }

  // Auto-fix PR — open/update one PR with paste-ready fix prompts.
  if (createPr && response.ok && repo && token) {
    try {
      const prUrl = await createFixPr(repo, token, fixBranch, url, response)
      if (prUrl) {
        setOutput('fix-pr-url', prUrl)
        process.stdout.write(`Fixes PR ready: ${prUrl}\n`)
      }
    } catch (e) {
      process.stderr.write(`::warning::Could not create fixes PR: ${e instanceof Error ? e.message : String(e)}\n`)
    }
  }

  // Exit code logic — gate the action on configured severity floor.
  if (!response.ok) {
    process.exit(failOn === 'never' ? 0 : 1)
  }
  const tot = response.totals
  if (failOn === 'critical' && tot.critical > 0) process.exit(1)
  if (failOn === 'warn' && (tot.critical > 0 || tot.warn > 0)) process.exit(1)
  if (failOn === 'info' && (tot.critical > 0 || tot.warn > 0 || tot.info > 0)) process.exit(1)
  process.exit(0)
}

main().catch((e) => {
  fail(`Unexpected error: ${e instanceof Error ? e.message : String(e)}`)
})
