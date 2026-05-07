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

  // Per-method fix prompt — copy-paste actionable, not vague.
  const fixSteps =
    method === 'file'
      ? [
          `Your verification method: file challenge.`,
          `1. Create a file at this exact path on your site:`,
          `   https://${domain}/.well-known/Vguard-verify.txt`,
          `2. The file's contents must be EXACTLY this UUID (no whitespace, no line breaks, no extra text):`,
          `   ${uuid}`,
          `3. The file must return HTTP 200 with the UUID as the body. Verify with:`,
          `   curl -s "https://${domain}/.well-known/Vguard-verify.txt"`,
          `4. Common pitfalls:`,
          `   • SPA routing returns index.html for unknown paths — add an explicit static rule for /.well-known/.`,
          `   • Wrong line endings — make sure the file has no trailing \\n if your editor adds one.`,
          `   • Wrong path case — Vguard-verify.txt is case-sensitive on Linux servers.`,
        ]
      : method === 'dns'
        ? [
            `Your verification method: DNS TXT record.`,
            `1. Add this TXT record at your DNS provider:`,
            `   Type:  TXT`,
            `   Name:  _Vguard-verify.${domain}`,
            `   Value: ${uuid}`,
            `   TTL:   600`,
            `2. Wait 30 seconds to 5 minutes for DNS propagation.`,
            `3. Verify it's live with:`,
            `   dig +short TXT _Vguard-verify.${domain}`,
            `4. Common pitfalls:`,
            `   • Some registrars auto-append the domain to the Name field — paste only "_Vguard-verify".`,
            `   • Quotes around the value: most registrars want the bare UUID; some need the value in quotes. If propagation works for other TXT records, copy that style.`,
            `   • Wildcard CAA at apex blocking the TXT — unrelated, but check if dig fails.`,
          ]
        : [
            `Your verification method: Vercel personal access token.`,
            `1. Go to https://vercel.com/account/tokens — generate a new token with FULL ACCESS scope.`,
            `2. Make sure you're signed in with the Vercel account that ACTUALLY owns ${domain}. If the domain is on a Vercel TEAM, the token must be created by a member of that team.`,
            `3. Paste the fresh token into the Vguard verification form.`,
            `4. Vguard will call /v9/projects/<id>/domains and look for ${domain} aliased to one of your projects.`,
            `5. Common pitfalls:`,
            `   • Token from the wrong account (personal vs team).`,
            `   • Token expired or revoked — check the token list at vercel.com/account/tokens.`,
            `   • ${domain} is not actually bound to a Vercel project — verify in the Vercel dashboard before retrying.`,
          ]

  const text =
    `Verification of ${domain} failed.\n\n` +
    `Method:  ${methodLabel}\n` +
    `Reason:  ${reason}\n` +
    `Time:    ${new Date().toISOString()}\n\n` +
    `How to fix:\n\n` +
    fixSteps.join('\n') +
    `\n\nWhen you're ready, retry verification: ${retryLink}\n\n` +
    `Need help? Reply to this email or contact infovguards@gmail.com.\n\n` +
    `— V-Guards`

  const html = `
<div style="font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#111;max-width:600px;line-height:1.5">
  <div style="background:#09090b;color:#ff6b6b;padding:18px 24px;border-radius:8px 8px 0 0;font-family:ui-monospace,SF Mono,Consolas,monospace;display:flex;align-items:center;gap:10px">
    <img src="https://v-guards.com/logo-200.png" alt="V-Guards" width="28" height="28" style="display:inline-block;vertical-align:middle;margin-right:8px;border-radius:6px" />
    <strong style="vertical-align:middle">V-Guards</strong>
    <span style="vertical-align:middle"> · verification failed ⚠</span>
  </div>
  <div style="border:1px solid #eee;border-top:none;padding:24px;border-radius:0 0 8px 8px">
    <p style="margin:0 0 16px;font-size:16px"><strong>${escapeHtml(domain)}</strong> couldn't be verified.</p>
    <table style="border-collapse:collapse;font-size:14px;margin-bottom:20px">
      <tr><td style="padding:4px 16px 4px 0;color:#666">Method</td><td>${escapeHtml(methodLabel)}</td></tr>
      <tr><td style="padding:4px 16px 4px 0;color:#666">Reason</td><td style="font-family:ui-monospace,monospace;font-size:13px;color:#cc0000">${escapeHtml(reason)}</td></tr>
      <tr><td style="padding:4px 16px 4px 0;color:#666">Time</td><td>${new Date().toISOString()}</td></tr>
    </table>
    <h3 style="margin:0 0 8px;font-size:14px;color:#222">How to fix</h3>
    <pre style="background:#f6f8fa;border:1px solid #e1e4e8;border-radius:6px;padding:12px;font-size:12px;line-height:1.45;overflow-x:auto;white-space:pre-wrap">${escapeHtml(fixSteps.join('\n'))}</pre>
    <p style="margin:20px 0 0">
      <a href="${retryLink}" style="display:inline-block;background:#22d3ee;color:#09090b;text-decoration:none;padding:10px 20px;border-radius:6px;font-weight:600">Retry verification →</a>
    </p>
    <p style="margin:24px 0 0;color:#888;font-size:12px">Need help? Reply to this email or contact <a href="mailto:infovguards@gmail.com" style="color:#06b6d4">infovguards@gmail.com</a>.</p>
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
