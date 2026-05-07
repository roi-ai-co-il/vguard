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
