// Test-runner resolve hook: map a `.js` relative specifier to its `.ts`
// sibling when the `.js` file doesn't exist on disk.
//
// WHY THIS EXISTS: Vercel compiles api functions to .js, so relative imports
// between them MUST use the `.js` extension (a `.ts` specifier → ERR_MODULE_
// NOT_FOUND / FUNCTION_INVOCATION_FAILED in production). But `node --test
// --experimental-strip-types` runs the raw .ts sources and does NOT rewrite
// `.js`→`.ts` for value imports. Without this hook, a Vercel-correct `.js`
// import breaks the local tests. The hook lets the SAME source satisfy both:
// `.js` on disk wins (prod parity); otherwise fall back to the `.ts` sibling.
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

export async function resolve(specifier, context, next) {
  if (/^\.{1,2}\//.test(specifier) && specifier.endsWith('.js') && context.parentURL) {
    try {
      const jsUrl = new URL(specifier, context.parentURL)
      if (!existsSync(fileURLToPath(jsUrl))) {
        const tsSpecifier = specifier.slice(0, -3) + '.ts'
        if (existsSync(fileURLToPath(new URL(tsSpecifier, context.parentURL)))) {
          return next(tsSpecifier, context)
        }
      }
    } catch {
      // fall through to default resolution
    }
  }
  return next(specifier, context)
}
