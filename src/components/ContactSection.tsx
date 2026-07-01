import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { Send, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react'

const revealUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0 },
}

const TURNSTILE_SITE_KEY = '0x4AAAAAAC_BzqF_UH-VXX5R'

// `window.turnstile` is augmented in src/pages/AdminDashboard.tsx — a single
// canonical declaration there avoids "subsequent property declarations must
// have the same type" errors.

type State = 'idle' | 'sending' | 'sent' | 'error'

export default function ContactSection() {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')
  const [state, setState] = useState<State>('idle')
  const [errorMsg, setErrorMsg] = useState('')
  const [turnstileToken, setTurnstileToken] = useState('')
  const turnstileRef = useRef<HTMLDivElement>(null)
  const widgetIdRef = useRef<string | null>(null)

  useEffect(() => {
    let attempt = 0
    const tryRender = () => {
      if (!turnstileRef.current) return
      if (window.turnstile) {
        widgetIdRef.current = window.turnstile.render(turnstileRef.current, {
          sitekey: TURNSTILE_SITE_KEY,
          theme: 'dark',
          size: 'normal',
          callback: (t: string) => setTurnstileToken(t),
          'error-callback': () => setTurnstileToken(''),
          'expired-callback': () => setTurnstileToken(''),
        }) ?? null
        return
      }
      if (attempt++ < 50) setTimeout(tryRender, 200)
    }
    tryRender()
    return () => {
      if (widgetIdRef.current && window.turnstile) {
        try {
          window.turnstile.reset(widgetIdRef.current)
        } catch {
          // ignore
        }
      }
    }
  }, [])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (state === 'sending') return
    setState('sending')
    setErrorMsg('')
    try {
      const r = await fetch('/api/contact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, message, turnstileToken }),
      })
      const j = (await r.json()) as { ok?: boolean; error?: string }
      if (j.ok) {
        setState('sent')
        setName('')
        setEmail('')
        setMessage('')
        setTurnstileToken('')
        if (widgetIdRef.current && window.turnstile) {
          try {
            window.turnstile.reset(widgetIdRef.current)
          } catch {
            // ignore
          }
        }
      } else {
        setState('error')
        setErrorMsg(j.error === 'turnstile_failed' ? 'Captcha verification failed — please try again.' : j.error === 'rate_limited' ? 'Too many requests. Wait a minute and try again.' : j.error === 'invalid_email' ? 'Please enter a valid email address.' : j.error === 'name_too_short' ? 'Please enter your name.' : j.error === 'message_too_short' ? 'Please write a longer message (10+ characters).' : 'Something went wrong. Please try again or email us directly.')
      }
    } catch {
      setState('error')
      setErrorMsg('Network error. Please try again or email us directly.')
    }
  }

  return (
    <section
      id="contact"
      className="relative max-w-3xl mx-auto px-4 sm:px-6 py-20 sm:py-28"
      aria-labelledby="contact-heading"
    >
      <motion.div
        initial="hidden"
        animate="show"
        variants={{ hidden: {}, show: { transition: { staggerChildren: 0.1, delayChildren: 0.05 } } }}
      >
        <motion.div
          variants={revealUp}
          transition={{ duration: 0.5 }}
          className="font-mono text-xs tracking-widest uppercase text-(--color-accent) mb-3"
        >
          Contact us
        </motion.div>
        <motion.h2
          variants={revealUp}
          transition={{ duration: 0.5 }}
          id="contact-heading"
          className="text-3xl sm:text-4xl font-bold tracking-tight mb-3"
        >
          Have a question, found a bug, or want to chat?
        </motion.h2>
        <motion.p
          variants={revealUp}
          transition={{ duration: 0.5 }}
          className="text-(--color-fg-muted) text-base sm:text-lg mb-8"
        >
          Drop us a line — we read every message and reply within 2 business days.
        </motion.p>

        <motion.form variants={revealUp} transition={{ duration: 0.5 }} onSubmit={submit} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label htmlFor="contact-name" className="block text-xs font-mono uppercase tracking-wider text-(--color-fg-dim) mb-1.5">
              Name
            </label>
            <input
              id="contact-name"
              type="text"
              required
              minLength={2}
              maxLength={100}
              value={name}
              onChange={(e) => setName(e.target.value)}
              autoComplete="name"
              disabled={state === 'sending' || state === 'sent'}
              className="w-full bg-(--color-surface) border border-(--color-border) rounded-md px-3 py-2.5 text-sm text-(--color-fg) placeholder:text-(--color-fg-dim) focus:outline-none focus:border-(--color-accent-border) disabled:opacity-60"
              placeholder="Jane Founder"
            />
          </div>
          <div>
            <label htmlFor="contact-email" className="block text-xs font-mono uppercase tracking-wider text-(--color-fg-dim) mb-1.5">
              Email
            </label>
            <input
              id="contact-email"
              type="email"
              required
              maxLength={200}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              disabled={state === 'sending' || state === 'sent'}
              className="w-full bg-(--color-surface) border border-(--color-border) rounded-md px-3 py-2.5 text-sm text-(--color-fg) placeholder:text-(--color-fg-dim) focus:outline-none focus:border-(--color-accent-border) disabled:opacity-60"
              placeholder="jane@your-app.com"
            />
          </div>
        </div>
        <div>
          <label htmlFor="contact-message" className="block text-xs font-mono uppercase tracking-wider text-(--color-fg-dim) mb-1.5">
            Message
          </label>
          <textarea
            id="contact-message"
            required
            minLength={10}
            maxLength={4000}
            rows={5}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            disabled={state === 'sending' || state === 'sent'}
            className="w-full bg-(--color-surface) border border-(--color-border) rounded-md px-3 py-2.5 text-sm text-(--color-fg) placeholder:text-(--color-fg-dim) focus:outline-none focus:border-(--color-accent-border) disabled:opacity-60 resize-y"
            placeholder="Tell us what's on your mind…"
          />
        </div>

        <div ref={turnstileRef} className="flex justify-start" />

        {state === 'error' && (
          <div role="alert" className="flex items-start gap-2 text-sm text-(--color-danger) bg-(--color-danger-muted) border border-(--color-danger)/30 rounded-md px-3 py-2">
            <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>{errorMsg}</span>
          </div>
        )}
        {state === 'sent' && (
          <div role="status" className="flex items-start gap-2 text-sm text-(--color-ok) bg-(--color-ok)/10 border border-(--color-ok)/30 rounded-md px-3 py-2">
            <CheckCircle2 size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>Got it — your message landed in our inbox. We'll get back to you within 2 business days.</span>
          </div>
        )}

        <div className="flex items-center justify-between gap-3 pt-2">
          <p className="text-xs text-(--color-fg-dim)">
            Or email us directly at{' '}
            <a href="mailto:infovguards@gmail.com" className="text-(--color-accent) hover:underline">
              infovguards@gmail.com
            </a>
          </p>
          <button
            type="submit"
            disabled={state === 'sending' || state === 'sent' || !turnstileToken}
            className="inline-flex items-center gap-2 bg-(--color-accent) text-(--color-bg) font-medium text-sm px-5 py-2.5 rounded-md hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-(--color-accent) focus-visible:ring-offset-2 focus-visible:ring-offset-(--color-bg) transition-opacity"
          >
            {state === 'sending' ? (
              <>
                <Loader2 size={16} className="animate-spin" aria-hidden="true" />
                Sending…
              </>
            ) : state === 'sent' ? (
              <>
                <CheckCircle2 size={16} aria-hidden="true" />
                Sent
              </>
            ) : (
              <>
                <Send size={16} aria-hidden="true" />
                Send message
              </>
            )}
          </button>
        </div>
        </motion.form>
      </motion.div>
    </section>
  )
}
