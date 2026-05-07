import { ArrowLeft } from 'lucide-react'

export default function Accessibility() {
  return (
    <div className="min-h-screen bg-(--color-bg) text-(--color-fg)">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 py-12 sm:py-16">
        <div className="flex items-center justify-between mb-10">
          <a
            href="/"
            className="inline-flex items-center gap-2 font-mono text-[11px] sm:text-xs text-(--color-fg-dim) hover:text-(--color-fg) transition-colors"
          >
            <ArrowLeft size={14} aria-hidden="true" />
            <span>V-Guards</span>
          </a>
          <span className="font-mono text-[10px] sm:text-[11px] text-(--color-fg-dim) tracking-widest uppercase">
            Accessibility
          </span>
        </div>

        <h1 className="text-3xl sm:text-4xl font-bold tracking-tight mb-2">Accessibility Statement</h1>
        <p className="text-(--color-fg-muted) text-sm mb-10">
          Last updated: May 7, 2026
        </p>

        <div className="space-y-6 text-sm sm:text-base leading-relaxed text-(--color-fg-muted)">
          <Section title="Our commitment">
            <p>
              ROI AI is committed to making V-Guards (
              <a href="https://v-guards.com" className="text-(--color-accent) hover:underline">
                https://v-guards.com
              </a>
              ) accessible to the widest possible audience, regardless of ability or technology.
              We strive to follow web accessibility best practices and continually improve the
              experience for all visitors.
            </p>
          </Section>

          <Section title="Conformance level">
            <p>
              The site is built to meet the{' '}
              <a
                href="https://www.w3.org/TR/WCAG21/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-(--color-accent) hover:underline"
              >
                Web Content Accessibility Guidelines (WCAG) 2.1 Level AA
              </a>
              . These guidelines explain how to make web content more accessible for people with
              disabilities and more user-friendly for everyone.
            </p>
          </Section>

          <Section title="Accessibility tools on this site">
            <p>
              Click the floating accessibility button at the bottom-right of any page to access
              personal display preferences:
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>Adjust text size from 75% up to 150%</li>
              <li>Switch on high-contrast mode</li>
              <li>Underline all links for stronger visual cues</li>
              <li>Pause animations and auto-rotating content</li>
              <li>Reset all preferences with one click</li>
            </ul>
            <p>
              Your preferences are stored locally in your browser (<code>localStorage</code>) and
              are restored automatically on your next visit. Nothing is sent to our servers.
            </p>
          </Section>

          <Section title="What we've already implemented">
            <ul className="list-disc pl-5 space-y-1">
              <li>Color contrast that meets the AA threshold</li>
              <li>ARIA labels on every interactive control</li>
              <li>Full keyboard navigation, including a visible focus ring</li>
              <li>Semantic HTML headings, landmarks, and form labels</li>
              <li>
                Respect for the operating system's <code>prefers-reduced-motion</code> setting
              </li>
              <li>Live-region announcements for dynamic content (e.g. the rotating headline)</li>
              <li>Forms with linked labels, descriptive errors, and clear recovery paths</li>
              <li>Text resize-friendly layout — content reflows without breaking up to 200% zoom</li>
            </ul>
          </Section>

          <Section title="Areas we're still improving">
            <p>
              A few areas have not yet reached our target conformance level:
            </p>
            <ul className="list-disc pl-5 space-y-1">
              <li>
                The interactive globe on the home page is decorative — the same data appears as a
                text list directly below it, but the canvas itself isn't keyboard-operable.
              </li>
              <li>
                Embedded illustrative code snippets in the "What we scan" section have descriptive
                surrounding context but are not yet fully exposed via screen-reader-friendly markup.
              </li>
            </ul>
            <p>
              We're actively working on these and will update this statement as fixes ship.
            </p>
          </Section>

          <Section title="Report an issue">
            <p>
              Found a barrier we missed, or have feedback on the accessibility of this site? We'd
              like to hear about it. We'll respond within 7 business days.
            </p>
            <ul className="list-none space-y-1">
              <li>
                <span className="text-(--color-fg)">Accessibility lead:</span> Roy Argaman
              </li>
              <li>
                <span className="text-(--color-fg)">Email:</span>{' '}
                <a
                  href="mailto:infovguards@gmail.com?subject=Accessibility%20feedback"
                  className="text-(--color-accent) hover:underline"
                >
                  infovguards@gmail.com
                </a>
              </li>
              <li>
                <span className="text-(--color-fg)">Response window:</span> 7 business days, any
                day of the week
              </li>
            </ul>
          </Section>

          <Section title="Statement updates">
            <p>
              This statement was first published on May 7, 2026 and will be revised as the site
              evolves and as our accessibility infrastructure improves.
            </p>
          </Section>
        </div>
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="text-(--color-fg) font-semibold text-base sm:text-lg mb-2">{title}</h2>
      <div className="space-y-2">{children}</div>
    </section>
  )
}
