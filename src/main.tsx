import { StrictMode, lazy, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import AccessibilityWidget from './components/AccessibilityWidget.tsx'

const AdminLogs = lazy(() => import('./pages/AdminLogs.tsx'))
const Privacy = lazy(() => import('./pages/Privacy.tsx'))
const AccessibilityPage = lazy(() => import('./pages/Accessibility.tsx'))

function pickRoute() {
  const path = window.location.pathname
  if (path === '/privacy' || path === '/privacy/') return <Privacy />
  if (path === '/accessibility' || path === '/accessibility/') return <AccessibilityPage />
  if (path === '/' || path === '' || path === '/terms' || path === '/terms/') return <App />
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
