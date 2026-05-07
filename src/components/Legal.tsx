import { ArrowLeft } from 'lucide-react'

interface Section {
  heading: string
  level: 2 | 3 | 4
  body?: string
  bullets?: string[]
}

interface LegalDocument {
  title: string
  intro: string[]
  sections: Section[]
}

const TERMS: LegalDocument = {
  title: 'Terms of Service',
  intro: [
    '⚠️ AI can make mistakes. V-Guards uses automated and AI-assisted detection — findings may be incomplete, inaccurate, or include false positives. Verify every finding independently before acting on it. Do not rely on V-Guards as your sole security audit, especially before a production deploy or audit-grade engagement.',
    'By using V-Guards you accept the terms below, including the No Warranty (§3), AI Disclaimer (§4), and Limitation of Liability (§5) clauses. All usage is at your own risk.',
  ],
  sections: [
    {
      level: 2,
      heading: '1. Purpose of Service',
      body: 'V-Guards is a security analysis tool intended solely for defensive and educational purposes. The platform is designed to help users identify potential security weaknesses in systems they own or are explicitly authorized to test.',
    },
    {
      level: 2,
      heading: '2. User Responsibility',
      body: 'By using this service, you agree that:',
      bullets: [
        'You will only scan domains, applications, or systems that you own or have explicit permission to test.',
        'You are solely responsible for all actions performed using this platform.',
        'You will not use V-Guards for malicious, unauthorized, or illegal activities.',
      ],
    },
    {
      level: 2,
      heading: '3. No Warranty',
      body: 'V-Guards is provided "as is" without warranties of any kind. We do not guarantee:',
      bullets: [
        'Accuracy of findings',
        'Completeness of results',
        'Absence of false positives or false negatives',
      ],
    },
    {
      level: 2,
      heading: '',
      body: 'Security analysis, especially AI-assisted analysis, may produce incorrect or incomplete results.',
    },
    {
      level: 2,
      heading: '4. AI Disclaimer',
      body: 'This platform uses automated and AI-based detection methods. You acknowledge that:',
      bullets: [
        'AI may misinterpret data',
        'AI-generated results may be inaccurate',
        'Findings should not be relied upon without independent verification',
      ],
    },
    {
      level: 2,
      heading: '5. Limitation of Liability',
      body: 'Under no circumstances shall V-Guards or its operators be liable for:',
      bullets: [
        'Any damages resulting from use of the platform',
        'Misuse of findings',
        'Unauthorized testing performed by users',
      ],
    },
    {
      level: 2,
      heading: '',
      body: 'All usage is at your own risk.',
    },
    {
      level: 2,
      heading: '6. Authorization Requirement',
      body: 'Certain advanced features (e.g., deep scanning, active probing) require proof of domain ownership. Attempting to bypass these safeguards is strictly prohibited.',
    },
    {
      level: 2,
      heading: '7. Compliance with Law',
      body: 'You agree to comply with all applicable laws and regulations, including cybersecurity and data protection laws.',
    },
    {
      level: 2,
      heading: '8. Service Changes',
      body: 'We reserve the right to modify, suspend, or terminate the service at any time without notice.',
    },
    {
      level: 2,
      heading: '9. Acceptance',
      body: 'By using V-Guards, you confirm that you have read, understood, and agreed to these Terms.',
    },
  ],
}

const PRIVACY: LegalDocument = {
  title: 'Privacy Policy',
  intro: [
    'V-Guards is a web security analysis platform designed to help users identify potential vulnerabilities in websites and applications.',
    'This Privacy Policy explains what data we collect, how we use it, and your rights regarding that data.',
  ],
  sections: [
    { level: 2, heading: '2. Information We Collect' },
    {
      level: 3,
      heading: '2.1 Data Provided by Users',
      body: 'When you use V-Guards, you may provide:',
      bullets: [
        'Website URLs for scanning',
        'Domain ownership verification data (e.g., DNS records or verification files)',
      ],
    },
    { level: 3, heading: '2.2 Automatically Collected Data' },
    {
      level: 4,
      heading: 'Stage 1 (Public Scan)',
      bullets: [
        'Target website HTML content',
        'HTTP headers and response metadata',
        'DNS records (e.g., SPF, DMARC, DNSSEC)',
        'TLS/SSL certificate information',
      ],
    },
    {
      level: 4,
      heading: 'Stage 2 (Browser-Assisted Scan)',
      body: 'With your explicit action (bookmarklet or extension), we may collect:',
      bullets: [
        'Cookie names (not values, unless explicitly required for analysis)',
        'LocalStorage and sessionStorage keys',
        'Network requests (API endpoints accessed during session)',
        'Browser environment data (user agent, performance metadata)',
      ],
    },
    {
      level: 3,
      heading: '2.3 Sensitive Data Handling',
      body: 'We aim to avoid collecting sensitive personal data. However, due to the nature of security analysis, some data may include:',
      bullets: [
        'Authentication tokens (e.g., JWTs)',
        'Identifiers (user IDs, emails if exposed by the scanned system)',
      ],
    },
    {
      level: 3,
      heading: '',
      body: 'Such data is:',
      bullets: [
        'Processed automatically',
        'Not used for tracking individuals',
        'Not sold or shared with third parties',
      ],
    },
    {
      level: 2,
      heading: '3. How We Use Information',
      body: 'We use collected data to:',
      bullets: [
        'Perform security analysis',
        'Detect vulnerabilities and misconfigurations',
        'Improve detection accuracy and system performance',
        'Generate reports for users',
      ],
    },
    {
      level: 2,
      heading: '4. Data Retention',
      bullets: [
        'Stage 1 scan results may be stored for a limited time for performance and debugging',
        'Stage 2 collected data is stored temporarily (e.g., up to 1 hour)',
        'Verified domain ownership records may be stored for up to 30 days',
      ],
    },
    {
      level: 2,
      heading: '',
      body: 'We do not retain data longer than necessary.',
    },
    {
      level: 2,
      heading: '5. Data Sharing',
      body: 'We do not sell, rent, or trade user data. Data may only be shared:',
      bullets: ['When required by law', 'To protect the integrity and security of the platform'],
    },
    {
      level: 2,
      heading: '6. Security Measures',
      body: 'We implement reasonable technical and organizational safeguards to protect data, including:',
      bullets: ['Access controls', 'Secure storage practices', 'Minimization of collected data'],
    },
    {
      level: 2,
      heading: '',
      body: 'However, no system is completely secure.',
    },
    {
      level: 2,
      heading: '7. User Responsibility',
      body: 'You are responsible for:',
      bullets: [
        'Only scanning systems you own or are authorized to test',
        'Ensuring compliance with applicable laws',
      ],
    },
    {
      level: 2,
      heading: '8. Your Rights',
      body: 'Depending on your jurisdiction (e.g., GDPR or חוק הגנת הפרטיות), you may have the right to:',
      bullets: [
        'Request access to your data',
        'Request deletion of your data',
        'Object to processing',
      ],
    },
    { level: 2, heading: '', body: 'To exercise these rights, contact us.' },
    {
      level: 2,
      heading: '9. Third-Party Services',
      body: 'V-Guards may interact with external services (e.g., DNS resolvers, cloud providers). These services operate under their own privacy policies.',
    },
    {
      level: 2,
      heading: '10. Changes to This Policy',
      body: 'We may update this Privacy Policy from time to time. Continued use of the service constitutes acceptance of the updated policy.',
    },
    {
      level: 2,
      heading: '11. Contact',
      body: 'For privacy-related questions, please contact: hello@roiai.co.il',
    },
  ],
}

function SectionView({ section }: { section: Section }) {
  return (
    <div className="mb-8">
      {section.heading &&
        (section.level === 2 ? (
          <h2 className="text-xl sm:text-2xl font-semibold tracking-tight mt-10 mb-3 text-(--color-fg)">
            {section.heading}
          </h2>
        ) : section.level === 3 ? (
          <h3 className="text-lg sm:text-xl font-semibold tracking-tight mt-6 mb-2 text-(--color-fg)">
            {section.heading}
          </h3>
        ) : (
          <h4 className="text-[15px] sm:text-base font-semibold tracking-tight mt-4 mb-2 text-(--color-fg-muted)">
            {section.heading}
          </h4>
        ))}
      {section.body && (
        <p className="text-[14px] sm:text-base text-(--color-fg-muted) leading-relaxed">
          {section.body}
        </p>
      )}
      {section.bullets && (
        <ul className="mt-2 space-y-1.5 text-[14px] sm:text-base text-(--color-fg-muted) leading-relaxed list-disc pl-5">
          {section.bullets.map((b, i) => (
            <li key={i}>{b}</li>
          ))}
        </ul>
      )}
    </div>
  )
}

function LegalDocumentView({ doc }: { doc: LegalDocument }) {
  return (
    <div className="min-h-screen flex flex-col bg-(--color-bg) text-(--color-fg) overflow-x-hidden">
      <header className="border-b border-(--color-border) sticky top-0 z-20 bg-(--color-bg)/85 backdrop-blur-md">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 h-12 sm:h-14 flex items-center justify-between gap-4">
          <a
            href="/"
            className="inline-flex items-center gap-2 font-mono text-[11px] sm:text-xs text-(--color-fg-dim) hover:text-(--color-fg) transition-colors"
          >
            <ArrowLeft size={14} aria-hidden="true" />
            <span>V-Guards</span>
          </a>
          <span className="font-mono text-[10px] sm:text-[11px] text-(--color-fg-dim) tracking-widest uppercase">
            Legal
          </span>
        </div>
      </header>

      <main className="flex-1">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 py-12 sm:py-16">
          <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight text-balance mb-6">
            {doc.title}
          </h1>
          {doc.intro.map((p, i) => (
            <p
              key={i}
              className="text-[14px] sm:text-base text-(--color-fg-muted) leading-relaxed mb-3"
            >
              {p}
            </p>
          ))}
          <div className="mt-4">
            {doc.sections.map((s, i) => (
              <SectionView key={i} section={s} />
            ))}
          </div>
          <p className="mt-12 font-mono text-[11px] sm:text-xs text-(--color-fg-dim)">
            Last updated: 2026-05-06
          </p>
        </div>
      </main>

      <footer className="border-t border-(--color-border) mt-auto">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 py-5 font-mono text-[11px] sm:text-xs text-(--color-fg-dim) flex flex-wrap items-center justify-between gap-3">
          <span>© 2026 V-Guards</span>
          <div className="flex items-center gap-4">
            <a href="/terms" className="hover:text-(--color-fg) transition-colors">
              Terms
            </a>
            <a href="/privacy" className="hover:text-(--color-fg) transition-colors">
              Privacy
            </a>
            <a href="/" className="hover:text-(--color-fg) transition-colors">
              Home
            </a>
          </div>
        </div>
      </footer>
    </div>
  )
}

export function TermsPage() {
  return <LegalDocumentView doc={TERMS} />
}

export function PrivacyPage() {
  return <LegalDocumentView doc={PRIVACY} />
}
