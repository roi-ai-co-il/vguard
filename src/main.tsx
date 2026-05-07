import { StrictMode, lazy, Suspense } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

const AdminLogs = lazy(() => import('./pages/AdminLogs.tsx'))
const Privacy = lazy(() => import('./pages/Privacy.tsx'))

function pickRoute() {
  const path = window.location.pathname
  if (path === '/privacy' || path === '/privacy/') return <Privacy />
  if (path === '/' || path === '' || path === '/terms' || path === '/terms/') return <App />
  return <AdminLogs />
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Suspense fallback={<div style={{ minHeight: '100vh', background: '#09090b' }} />}>
      {pickRoute()}
    </Suspense>
  </StrictMode>,
)
