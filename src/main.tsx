import { StrictMode, lazy, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import AccessibilityWidget from './components/AccessibilityWidget.tsx'

// Promote the deferred Google Fonts <link> from media="print" → media="all"
// so the web fonts swap in. Pattern keeps the stylesheet off the critical
// render path (saves ~70ms FCP/LCP) without needing 'unsafe-inline' in CSP.
const fontsLink = document.getElementById('vg-fonts') as HTMLLinkElement | null
if (fontsLink) {
  if (fontsLink.sheet) {
    fontsLink.media = 'all'
  } else {
    fontsLink.addEventListener('load', () => {
      fontsLink.media = 'all'
    }, { once: true })
  }
}

const AdminLogs = lazy(() => import('./pages/AdminLogs.tsx'))
const Privacy = lazy(() => import('./pages/Privacy.tsx'))
const Terms = lazy(() => import('./pages/Terms.tsx'))
const AccessibilityPage = lazy(() => import('./pages/Accessibility.tsx'))

function pickRoute() {
  const path = window.location.pathname
  if (path === '/privacy' || path === '/privacy/') return <Privacy />
  if (path === '/terms' || path === '/terms/') return <Terms />
  if (path === '/accessibility' || path === '/accessibility/') return <AccessibilityPage />
  if (path === '/' || path === '') return <App />
  return <AdminLogs />
}

const isAdminRoute = (() => {
  const p = window.location.pathname
  return p !== '/' && p !== '' && p !== '/privacy' && p !== '/privacy/' && p !== '/terms' && p !== '/terms/' && p !== '/accessibility' && p !== '/accessibility/'
})()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Suspense fallback={<div style={{ minHeight: '100vh', background: '#09090b' }} />}>
      {pickRoute()}
    </Suspense>
    {!isAdminRoute && <AccessibilityWidget />}
  </StrictMode>,
)
