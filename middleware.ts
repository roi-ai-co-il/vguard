import { next, rewrite } from '@vercel/edge'

export const config = {
  matcher: '/((?!api/|assets/|favicon\\.ico|robots\\.txt|sitemap\\.xml|.*\\.(?:js|css|map|png|jpg|jpeg|svg|webp|ico|woff2?|ttf)).*)',
}

const NOINDEX = 'noindex, nofollow, noarchive'
const PUBLIC_SPA_PATHS = new Set([
  '/',
  '/how-it-works', '/how-it-works/',
  '/pricing', '/pricing/',
  '/contact', '/contact/',
  '/privacy', '/privacy/',
  '/terms', '/terms/',
  '/accessibility', '/accessibility/',
])

export default function middleware(req: Request): Response {
  const { pathname } = new URL(req.url)

  if (pathname === '/admin/logs' || pathname === '/admin/logs/' || pathname.startsWith('/admin/logs/')) {
    return new Response('Not Found', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'X-Robots-Tag': NOINDEX,
        'Cache-Control': 'no-store',
      },
    })
  }

  if (PUBLIC_SPA_PATHS.has(pathname)) return next()

  const adminPath = process.env.ADMIN_LOGS_PATH ?? ''
  if (
    adminPath.length > 0 &&
    adminPath.startsWith('/') &&
    (pathname === adminPath || pathname === adminPath + '/' || pathname.startsWith(adminPath + '/'))
  ) {
    const shell = new URL('/index.html', req.url)
    const res = rewrite(shell)
    res.headers.set('X-Robots-Tag', NOINDEX)
    res.headers.set('Cache-Control', 'no-store')
    return res
  }

  return next()
}
