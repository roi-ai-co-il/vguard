import { useEffect } from 'react'

export default function Privacy() {
  useEffect(() => {
    fetch('/api/track', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event_type: 'privacy_viewed', path: '/privacy' }),
    }).catch(() => {})
  }, [])

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      <article className="max-w-3xl mx-auto prose prose-invert space-y-6 py-8">
        <h1 className="text-3xl font-semibold">Privacy Policy</h1>
        <p className="text-zinc-400 text-sm">Last updated: 2026-05-07</p>

        <section className="space-y-3">
          <h2 className="text-xl font-medium">What we scan</h2>
          <p className="text-zinc-300">
            Vguard scans only the URLs you submit. We fetch publicly accessible HTML, JS bundles,
            and headers — the same content any browser would see.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-xl font-medium">Audit & Security Logs</h2>
          <p className="text-zinc-300">
            For abuse prevention and security monitoring, we keep an internal audit log of scan
            activity. Each entry retains:
          </p>
          <ul className="list-disc pl-6 text-zinc-300 space-y-1">
            <li>A salted SHA-256 hash of the requesting IP (never the raw IP).</li>
            <li>User-agent string and request path.</li>
            <li>Event type (e.g. <code>scan_started</code>, <code>scan_completed</code>) and high-level outcome.</li>
            <li>The URL you submitted to scan and the resulting Vibe Score.</li>
          </ul>
          <p className="text-zinc-300">
            We <strong>do not</strong> store cookies, authentication tokens, request bodies, raw IP
            addresses, or any sensitive values collected by Stage 2 client-side checks.
          </p>
          <p className="text-zinc-300">
            Audit logs are accessible only to Vguard staff over a server-side authenticated channel
            and are <strong>automatically deleted after 90 days</strong> via a scheduled database job.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-xl font-medium">No third-party tracking</h2>
          <p className="text-zinc-300">
            Vguard does not use third-party analytics or advertising trackers. The audit log
            described above is the only telemetry we collect, and it never leaves our infrastructure.
          </p>
        </section>

        <section className="space-y-3">
          <h2 className="text-xl font-medium">Contact</h2>
          <p className="text-zinc-300">
            Questions or removal requests: reach out via the contact link on the homepage.
          </p>
        </section>

        <p className="pt-6">
          <a href="/" className="text-zinc-400 hover:text-zinc-200 underline">← Back to V-Guards</a>
        </p>
      </article>
    </div>
  )
}
