// Registers the .js→.ts test resolve hook (see _ts-resolve.mjs). Loaded via
// `node --import ./api/__tests__/_register.mjs` before the test files run.
import { register } from 'node:module'
register('./_ts-resolve.mjs', import.meta.url)
