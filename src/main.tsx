import { StrictMode, lazy, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

const AdminLogs = lazy(() => import('./pages/AdminLogs.tsx'))
const Privacy = lazy(() => import('./pages/Privacy.tsx'))

function pickRoute() {
  const path = window.location.pathname
  if (path === '/admin/logs' || path === '/admin/logs/') return <AdminLogs />
  if (path === '/privacy' || path === '/privacy/') return <Privacy />
  return <App />
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Suspense fallback={<div style={{ minHeight: '100vh', background: '#09090b' }} />}>
      {pickRoute()}
    </Suspense>
  </StrictMode>,
)
