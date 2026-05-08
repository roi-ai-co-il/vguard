/**
 * Send a "domain verified" confirmation email to the verifier.
 *
 * Triggered after a successful Stage 3 ownership verification (file challenge,
 * DNS TXT, or Vercel token). Fire-and-forget — never blocks the verify
 * response, never throws upstream.
 *
 * Sender + recipient are both env-overridable so swapping inboxes / Resend
 * domains doesn't require a code change.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export async function sendVerificationConfirmation(
  toEmail: string,
  domain: string,
  method: 'file' | 'dns' | 'vercel',
): Promise<void> {
  const trimmed = (toEmail ?? '').trim()
  if (!trimmed || !EMAIL_RE.test(trimmed)) return
  const token = process.env.RESEND_TOKEN
  if (!token) return

  const fromAddress = process.env.VERIFY_FROM ?? process.env.CONTACT_FROM ?? 'V-Guards <noreply@v-guards.com>'
  const methodLabel =
    method === 'file' ? 'file challenge' : method === 'dns' ? 'DNS TXT record' : 'Vercel token'
  const subject = `✓ ${domain} is verified on V-Guards`

  const dashboardLink = 'https://v-guards.com/?url=' + encodeURIComponent(`https://${domain}/`)
  const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    .toISOString()
    .slice(0, 10)

  const text =
    `Domain ownership verified ✓\n\n` +
    `Domain:    ${domain}\n` +
    `Method:    ${methodLabel}\n` +
    `Verified:  ${new Date().toISOString()}\n` +
    `Expires:   ${expiresAt}\n\n` +
    `You can now run a Stage 3 deep scan on ${domain} — that includes:\n` +
    `  • Supabase RLS testing\n` +
    `  • Storage bucket write-probe\n` +
    `  • Aggressive XSS / SQLi payloads\n` +
    `  • Path traversal probing\n` +
    `  • AI prompt-injection canaries\n` +
    `  • IDOR testing (with optional JWT)\n\n` +
    `Run a deep scan: ${dashboardLink}\n\n` +
    `Verification expires after 30 days. You can re-verify any time.\n\n` +
    `— V-Guards`

  const html = `
<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#111;max-width:600px;line-height:1.5">
  <div style="background:#09090b;color:#22d3ee;padding:18px 24px;border-radius:8px 8px 0 0;font-family:ui-monospace,SF Mono,Consolas,monospace;display:flex;align-items:center;gap:10px">
    <img src="https://v-guards.com/logo-200.png" alt="V-Guards" width="28" height="28" style="display:inline-block;vertical-align:middle;margin-right:8px;border-radius:6px" />
    <strong style="vertical-align:middle">V-Guards</strong>
    <span style="vertical-align:middle"> · ownership verified ✓</span>
  </div>
  <div style="border:1px solid #eee;border-top:none;padding:24px;border-radius:0 0 8px 8px">
    <p style="margin:0 0 16px;font-size:16px"><strong>${escapeHtml(domain)}</strong> is now verified.</p>
    <table style="border-collapse:collapse;font-size:14px;margin-bottom:20px">
      <tr><td style="padding:4px 16px 4px 0;color:#666">Method</td><td>${escapeHtml(methodLabel)}</td></tr>
      <tr><td style="padding:4px 16px 4px 0;color:#666">Verified</td><td>${new Date().toISOString()}</td></tr>
      <tr><td style="padding:4px 16px 4px 0;color:#666">Expires</td><td>${expiresAt}</td></tr>
    </table>
    <p style="margin:0 0 12px">You can now run a <strong>Stage 3 deep scan</strong> on ${escapeHtml(domain)} — including Supabase RLS testing, storage bucket probes, aggressive XSS / SQLi payloads, path traversal, AI prompt-injection canaries, and IDOR testing.</p>
    <p style="margin:20px 0 0">
      <a href="${dashboardLink}" style="display:inline-block;background:#22d3ee;color:#09090b;text-decoration:none;padding:10px 20px;border-radius:6px;font-weight:600">Run deep scan →</a>
    </p>
    <p style="margin:24px 0 0;color:#888;font-size:12px">Verification expires after 30 days. You can re-verify any time at <a href="https://v-guards.com" style="color:#06b6d4">v-guards.com</a>.</p>
  </div>
</div>`.trim()

  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: fromAddress,
        to: [trimmed],
        subject,
        text,
        html,
      }),
    })
  } catch {
    // ignore — fail-soft, verify response already sent to client
  }
}

export function fireAndForget(p: Promise<unknown>): void {
  p.catch(() => {})
}

/**
 * Send a "verification failed" email when the user's challenge didn't pass.
 * Includes the precise reason + a copy-paste prompt for fixing the most common
 * cause per method. Fire-and-forget — never blocks the verify response.
 */
export async function sendVerificationFailure(
  toEmail: string,
  domain: string,
  method: 'file' | 'dns' | 'vercel',
  uuid: string,
  reason: string,
): Promise<void> {
  const trimmed = (toEmail ?? '').trim()
  if (!trimmed || !EMAIL_RE.test(trimmed)) return
  const token = process.env.RESEND_TOKEN
  if (!token) return

  const fromAddress =
    process.env.VERIFY_FROM ?? process.env.CONTACT_FROM ?? 'V-Guards <noreply@v-guards.com>'
  const methodLabel =
    method === 'file' ? 'file challenge' : method === 'dns' ? 'DNS TXT record' : 'Vercel token'
  const subject = `⚠ ${domain} verification failed — here's how to fix`
  const retryLink = 'https://v-guards.com/?url=' + encodeURIComponent(`https://${domain}/`)

  // Structured per-method fix guide. `kind: 'record'` blocks render as a
  // copy-friendly code box; `kind: 'p'` is a paragraph; `kind: 'h'` is a
  // section header with an emoji glyph.
  type Block =
    | { kind: 'p'; text: string }
    | { kind: 'h'; emoji: string; text: string }
    | { kind: 'record'; rows: Array<[string, string]> }
    | { kind: 'cmd'; text: string }
    | { kind: 'ul'; items: string[] }

  const fixBlocks: Block[] =
    method === 'file'
      ? [
          { kind: 'p', text: `We tried to fetch a verification file from your site but didn't find your code there. Don't worry — this is the most common method and it's a 1-minute fix.` },
          { kind: 'h', emoji: '📌', text: 'Step 1 — Create a file with your code' },
          { kind: 'p', text: `Create a plain-text file at this exact path on your site:` },
          { kind: 'cmd', text: `https://${domain}/.well-known/Vguard-verify.txt` },
          { kind: 'p', text: `The file's content must be EXACTLY this code, with no whitespace, line breaks, or extra characters:` },
          { kind: 'cmd', text: uuid },
          { kind: 'h', emoji: '✅', text: 'Step 2 — Confirm it\'s live' },
          { kind: 'p', text: `Open the URL in your browser, or run this in a terminal:` },
          { kind: 'cmd', text: `curl -s "https://${domain}/.well-known/Vguard-verify.txt"` },
          { kind: 'p', text: `You should see your code returned. If you get HTML instead, your site is rewriting unknown paths to index.html — add an explicit static-file rule for /.well-known/ in your hosting config.` },
          { kind: 'h', emoji: '🛟', text: 'Watch out for' },
          { kind: 'ul', items: [
            `Some editors add an invisible newline at end of file — make sure the file is exactly the code, nothing else.`,
            `On Linux servers, file paths are case-sensitive: it's "Vguard-verify.txt" with a capital V.`,
            `If your hosting platform requires a build step, redeploy after adding the file.`,
          ] },
          { kind: 'h', emoji: '🚀', text: 'Then click "Retry verification" below' },
        ]
      : method === 'dns'
        ? [
            { kind: 'p', text: `We checked DNS for your verification code but didn't find it (or found a different one). Adding the right TXT record at your DNS provider takes about 2 minutes.` },
            { kind: 'h', emoji: '📌', text: 'Step 1 — Add this TXT record at your DNS provider' },
            { kind: 'record', rows: [
              ['Type',  'TXT'],
              ['Name',  `_Vguard-verify`],
              ['Value', uuid],
              ['TTL',   '600 (or your provider\'s default)'],
            ] },
            { kind: 'p', text: `Most providers have a "DNS" or "DNS Records" section in the dashboard for ${domain}. Use the prefix "_Vguard-verify" only — your provider auto-appends the rest of the domain.` },
            { kind: 'h', emoji: '🌐', text: 'Where to do this (most common)' },
            { kind: 'ul', items: [
              `GoDaddy → dcc.godaddy.com → portfolio → ${domain} → DNS Records → Add → TXT`,
              `Cloudflare → dash.cloudflare.com → ${domain} → DNS → Records → Add record → TXT`,
              `Vercel DNS → vercel.com/dashboard → Domains → ${domain} → DNS → Add record`,
              `Namecheap / IONOS / Google Domains — same pattern, look for "Add TXT record"`,
            ] },
            { kind: 'h', emoji: '⏱', text: 'Step 2 — Wait for DNS propagation' },
            { kind: 'p', text: `Usually 30 seconds to 5 minutes. Confirm it's live by running:` },
            { kind: 'cmd', text: `dig +short TXT _Vguard-verify.${domain}` },
            { kind: 'p', text: `You should see your code returned in quotes. Or use a web tool: open https://www.whatsmydns.net/#TXT/_Vguard-verify.${domain} — it shows propagation across many regions.` },
            { kind: 'h', emoji: '🛟', text: 'Watch out for' },
            { kind: 'ul', items: [
              `Don't paste the FULL "_Vguard-verify.${domain}" into the Name field — your provider adds the domain part automatically. Just "_Vguard-verify".`,
              `Don't add quotes around the value yourself. The provider handles the quoting in the actual DNS response.`,
              `If you already had a different verification code in DNS, you can either delete it and add this one, or click "Use this DNS code" in the V-Guards UI to adopt the existing one (faster — no propagation wait).`,
            ] },
            { kind: 'h', emoji: '🚀', text: 'Then click "Retry verification" below' },
          ]
        : [
            { kind: 'p', text: `Vercel didn't recognize the token, OR the token works but ${domain} isn't on the same Vercel account. Three things to check:` },
            { kind: 'h', emoji: '📌', text: 'Step 1 — Generate a fresh token' },
            { kind: 'ul', items: [
              `Open https://vercel.com/account/tokens`,
              `Click "Create" → name it "V-Guards verify"`,
              `Scope: "Full Access" (we use it once and discard — never stored)`,
              `Expiration: 1 day is fine`,
              `Copy the token immediately (Vercel shows it once)`,
            ] },
            { kind: 'h', emoji: '🌐', text: 'Step 2 — Make sure the account owns the domain' },
            { kind: 'p', text: `Open https://vercel.com/dashboard and find ${domain} under one of your projects' "Domains" tab. If you don't see it:` },
            { kind: 'ul', items: [
              `It might be on a different Vercel account (personal vs team) — switch accounts at top-left and check.`,
              `It might be on Vercel but not yet bound to any project — bind it first under Settings → Domains.`,
              `If ${domain} isn't on Vercel at all, use the file-challenge or DNS TXT method instead.`,
            ] },
            { kind: 'h', emoji: '🚀', text: 'Step 3 — Paste the fresh token and click Verify' },
            { kind: 'p', text: `V-Guards will call Vercel's /v9/projects API once with your token, look for ${domain} as a project alias, then discard the token. We never log it, never store it.` },
          ]

  const blockToText = (b: Block): string => {
    if (b.kind === 'p') return b.text
    if (b.kind === 'h') return `\n${b.emoji} ${b.text}`
    if (b.kind === 'cmd') return `    ${b.text}`
    if (b.kind === 'ul') return b.items.map((i) => `  • ${i}`).join('\n')
    if (b.kind === 'record') return b.rows.map(([k, v]) => `    ${k.padEnd(8)} ${v}`).join('\n')
    return ''
  }
  const text =
    `Verification of ${domain} failed.\n\n` +
    `Method:  ${methodLabel}\n` +
    `Reason:  ${reason}\n` +
    `Time:    ${new Date().toISOString()}\n\n` +
    `How to fix:\n\n` +
    fixBlocks.map(blockToText).join('\n') +
    `\n\nWhen you're ready, retry verification: ${retryLink}\n\n` +
    `Need help? Reply to this email or contact infovguards@gmail.com.\n\n` +
    `— V-Guards`

  const blockToHtml = (b: Block): string => {
    if (b.kind === 'p') {
      return `<p style="margin:8px 0;color:#374151;font-size:14px;line-height:1.6">${escapeHtml(b.text)}</p>`
    }
    if (b.kind === 'h') {
      return `<h3 style="margin:18px 0 8px;color:#111;font-size:14px;font-weight:700;display:flex;align-items:center;gap:6px"><span style="font-size:16px">${b.emoji}</span> ${escapeHtml(b.text)}</h3>`
    }
    if (b.kind === 'cmd') {
      return `<div style="background:#0f172a;color:#a3e9f4;font-family:ui-monospace,SF Mono,Consolas,monospace;font-size:13px;padding:12px 14px;border-radius:6px;margin:6px 0 10px;word-break:break-all;line-height:1.4">${escapeHtml(b.text)}</div>`
    }
    if (b.kind === 'ul') {
      const lis = b.items.map((i) => `<li style="margin:6px 0;color:#374151;font-size:13px;line-height:1.5">${escapeHtml(i)}</li>`).join('')
      return `<ul style="margin:6px 0 10px 22px;padding:0">${lis}</ul>`
    }
    if (b.kind === 'record') {
      const rows = b.rows
        .map(
          ([k, v]) =>
            `<tr><td style="padding:8px 14px;color:#9ca3af;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;font-weight:700;width:80px;border-bottom:1px solid #1e293b">${escapeHtml(k)}</td><td style="padding:8px 14px;color:#a3e9f4;font-family:ui-monospace,SF Mono,Consolas,monospace;font-size:13px;word-break:break-all;border-bottom:1px solid #1e293b">${escapeHtml(v)}</td></tr>`,
        )
        .join('')
      return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="width:100%;background:#0f172a;border-radius:8px;margin:8px 0 10px;border-collapse:collapse;overflow:hidden">${rows}</table>`
    }
    return ''
  }
  const fixHtmlList = fixBlocks.map(blockToHtml).join('')

  const html = `
<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#111;max-width:600px;line-height:1.5;margin:0 auto">
  <!-- Header -->
  <div style="background:#09090b;color:#ff6b6b;padding:20px 24px;border-radius:10px 10px 0 0;font-family:ui-monospace,SF Mono,Consolas,monospace">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="width:100%">
      <tr>
        <td style="vertical-align:middle;width:40px"><img src="https://v-guards.com/logo-200.png" alt="V-Guards" width="32" height="32" style="display:block;border-radius:7px" /></td>
        <td style="vertical-align:middle;padding-left:12px">
          <div style="font-size:15px"><strong style="color:#fff">V-Guards</strong> <span style="color:#888">·</span> <span style="color:#ff6b6b">verification failed ⚠</span></div>
        </td>
      </tr>
    </table>
  </div>

  <div style="border:1px solid #e5e7eb;border-top:none;padding:0;border-radius:0 0 10px 10px">
    <!-- Hero summary -->
    <div style="padding:24px 24px 8px">
      <p style="margin:0 0 4px;font-size:16px;color:#111"><strong>${escapeHtml(domain)}</strong> couldn't be verified.</p>
      <p style="margin:0;color:#666;font-size:13px">Don't worry — the fix is below, copy-paste ready.</p>
    </div>

    <!-- Method block -->
    <div style="padding:14px 24px;border-top:1px solid #f3f4f6">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#9ca3af;font-weight:600;margin-bottom:4px">Method</div>
      <div style="font-size:14px;color:#111">${escapeHtml(methodLabel)}</div>
    </div>

    <!-- Reason block -->
    <div style="padding:14px 24px;border-top:1px solid #f3f4f6;background:#fef2f2">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#dc2626;font-weight:600;margin-bottom:6px">Reason</div>
      <div style="font-size:13px;color:#7f1d1d;line-height:1.55;font-family:ui-monospace,SF Mono,Consolas,monospace;word-break:break-word">${escapeHtml(reason)}</div>
    </div>

    <!-- Time block -->
    <div style="padding:14px 24px;border-top:1px solid #f3f4f6">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#9ca3af;font-weight:600;margin-bottom:4px">Time</div>
      <div style="font-size:13px;color:#444;font-family:ui-monospace,SF Mono,Consolas,monospace">${new Date().toISOString()}</div>
    </div>

    <!-- How to fix block -->
    <div style="padding:20px 24px;border-top:1px solid #f3f4f6">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.06em;color:#06b6d4;font-weight:700;margin-bottom:14px">How to fix</div>
      <div>${fixHtmlList}</div>
    </div>

    <!-- CTA -->
    <div style="padding:0 24px 24px">
      <a href="${retryLink}" style="display:inline-block;background:#22d3ee;color:#09090b;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:700;font-size:14px">Retry verification →</a>
    </div>

    <!-- Footer -->
    <div style="padding:16px 24px;border-top:1px solid #f3f4f6;background:#fafafa;border-radius:0 0 10px 10px">
      <p style="margin:0;color:#6b7280;font-size:12px">Need help? Reply to this email or contact <a href="mailto:infovguards@gmail.com" style="color:#06b6d4;text-decoration:none">infovguards@gmail.com</a>.</p>
    </div>
  </div>
</div>`.trim()

  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ from: fromAddress, to: [trimmed], subject, text, html }),
    })
  } catch {
    // ignore — fail-soft, verify response already sent to client
  }
}
