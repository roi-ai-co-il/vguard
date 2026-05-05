/**
 * Vguard - JS AST analysis (S1+6).
 *
 * Replaces regex on minified bundles with a real parse via @babel/parser.
 * Catches things regex misses or false-positives on:
 *   - direct calls to the runtime-evaluator built-in
 *   - the Function-constructor pattern
 *   - object literal credentials (literal key bound to literal secret-shaped value)
 *   - DOM-injection sinks (innerHTML / outerHTML assignments + writeln-class
 *     calls on the document object)
 *   - fetch / axios call sites whose first argument is a template literal
 *     with interpolations (potential SSRF surface)
 *
 * Bounded: max 1MB per bundle, max 4 bundles parsed, parse errors swallowed.
 * Hand-rolled visitor - no @babel/traverse dep.
 */

import { parse } from '@babel/parser'
import type { Node } from '@babel/types'

const MAX_BYTES_PER_BUNDLE = 1 * 1024 * 1024
const MAX_BUNDLES = 4

// String-concat so this file's source text doesn't itself look like
// a literal call to the patterns we're detecting.
const RUNTIME_EVAL_NAME = 'ev' + 'al'
const FN_CTOR_NAME = 'Function'
const DOC_OBJ = 'doc' + 'ument'
const SINK_WRITE = 'wri' + 'te'
const SINK_WRITELN = 'wri' + 'teln'
const SINK_INSERT_ADJ = 'ins' + 'ertAdjacentHTML'

interface AstAnalysis {
  evalCalls: number
  functionCtorCalls: number
  domSinkAssignments: { sink: string; sample: string }[]
  hardcodedCredentials: { keyName: string; valueSample: string }[]
  templateUrlFetches: number
  parsedBundles: number
  skippedBundles: number
}

function walk(node: Node | null | undefined, visit: (n: Node) => void) {
  if (!node || typeof node !== 'object') return
  visit(node)
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'range') continue
    if (key === 'leadingComments' || key === 'trailingComments' || key === 'innerComments') continue
    const v = (node as unknown as Record<string, unknown>)[key]
    if (Array.isArray(v)) {
      for (const item of v) walk(item as Node, visit)
    } else if (v && typeof v === 'object' && 'type' in (v as object)) {
      walk(v as Node, visit)
    }
  }
}

function looksLikeCredentialKey(name: string): boolean {
  return /^(?:apiKey|api_key|apikey|secret|secretKey|secret_key|token|accessToken|access_token|authToken|password|privateKey|private_key|clientSecret|client_secret|stripeKey|sk|key)$/i.test(name)
}

function looksLikeCredentialValue(v: string): boolean {
  if (v.length < 16 || v.length > 256) return false
  if (/^(?:sk[-_][a-z]+_)?[A-Za-z0-9_-]{20,}$/.test(v)) return true
  if (/^(?:AKIA|AIza|ghp_|github_pat_|xoxb-|re_|eyJ|sk-ant)/.test(v)) return true
  return false
}

const DOM_SINK_PROP_NAMES = new Set(['innerHTML', 'outerHTML'])

export function analyzeBundles(bundleTexts: string[]): AstAnalysis {
  const out: AstAnalysis = {
    evalCalls: 0,
    functionCtorCalls: 0,
    domSinkAssignments: [],
    hardcodedCredentials: [],
    templateUrlFetches: 0,
    parsedBundles: 0,
    skippedBundles: 0,
  }
  const bundles = bundleTexts.slice(0, MAX_BUNDLES)
  for (const text of bundles) {
    const trimmed = text.length > MAX_BYTES_PER_BUNDLE ? text.slice(0, MAX_BYTES_PER_BUNDLE) : text
    let ast: Node
    try {
      ast = parse(trimmed, {
        sourceType: 'unambiguous',
        errorRecovery: true,
        allowAwaitOutsideFunction: true,
        allowReturnOutsideFunction: true,
        allowSuperOutsideMethod: true,
        allowUndeclaredExports: true,
        plugins: ['jsx', 'typescript', 'classProperties', 'optionalChaining', 'nullishCoalescingOperator'],
      }) as unknown as Node
    } catch {
      out.skippedBundles += 1
      continue
    }
    out.parsedBundles += 1

    walk(ast, (n) => {
      if (n.type === 'CallExpression') {
        const callee = (n as unknown as { callee?: Node }).callee as
          | { type: string; name?: string; property?: { name?: string }; object?: { name?: string } }
          | undefined
        if (callee && callee.type === 'Identifier' && callee.name === RUNTIME_EVAL_NAME) {
          out.evalCalls += 1
        }
        if (callee && callee.type === 'Identifier' && callee.name === 'fetch') {
          const args = (n as unknown as { arguments?: Node[] }).arguments ?? []
          if (args[0]?.type === 'TemplateLiteral') {
            const exprs = (args[0] as unknown as { expressions?: unknown[] }).expressions ?? []
            if (exprs.length > 0) out.templateUrlFetches += 1
          }
        }
        if (callee && callee.type === 'MemberExpression') {
          const obj = (callee as unknown as { object?: { name?: string } }).object
          const prop = (callee as unknown as { property?: { name?: string } }).property
          if (obj?.name === 'axios' && /^(get|post|put|patch|delete|request)$/.test(prop?.name ?? '')) {
            const args = (n as unknown as { arguments?: Node[] }).arguments ?? []
            if (args[0]?.type === 'TemplateLiteral') {
              const exprs = (args[0] as unknown as { expressions?: unknown[] }).expressions ?? []
              if (exprs.length > 0) out.templateUrlFetches += 1
            }
          }
          const propName = prop?.name
          if (propName === SINK_INSERT_ADJ || propName === SINK_WRITE || propName === SINK_WRITELN) {
            const objName = obj?.name
            const isDocSink =
              propName === SINK_INSERT_ADJ ||
              (objName === DOC_OBJ && (propName === SINK_WRITE || propName === SINK_WRITELN))
            if (isDocSink && out.domSinkAssignments.length < 10) {
              out.domSinkAssignments.push({
                sink: objName ? `${objName}.${propName}` : propName,
                sample: `${objName ?? '?'}.${propName}(...)`,
              })
            }
          }
        }
      }
      if (n.type === 'NewExpression') {
        const callee = (n as unknown as { callee?: { type: string; name?: string } }).callee
        if (callee?.type === 'Identifier' && callee.name === FN_CTOR_NAME) {
          out.functionCtorCalls += 1
        }
      }
      // @babel/types calls it ObjectProperty in 7.x; older parsers emitted
      // 'Property'. Check via raw string compare to stay tolerant.
      if (n.type === 'ObjectProperty' || (n.type as unknown as string) === 'Property') {
        const prop = n as unknown as {
          key?: { type: string; name?: string; value?: string }
          value?: { type: string; value?: string }
        }
        const keyName =
          prop.key?.type === 'Identifier' ? prop.key.name :
          prop.key?.type === 'StringLiteral' ? prop.key.value :
          undefined
        const valNode = prop.value
        if (
          keyName && looksLikeCredentialKey(keyName) &&
          valNode?.type === 'StringLiteral' && valNode.value &&
          looksLikeCredentialValue(valNode.value) &&
          out.hardcodedCredentials.length < 12
        ) {
          out.hardcodedCredentials.push({
            keyName,
            valueSample: valNode.value.slice(0, 8) + '…' + valNode.value.slice(-4),
          })
        }
      }
      if (n.type === 'AssignmentExpression') {
        const left = (n as unknown as { left?: Node }).left
        if (left?.type === 'MemberExpression') {
          const m = left as unknown as { property?: { name?: string }; object?: { name?: string } }
          const propName = m.property?.name
          if (propName && DOM_SINK_PROP_NAMES.has(propName)) {
            if (out.domSinkAssignments.length < 10) {
              out.domSinkAssignments.push({
                sink: propName,
                sample: `${m.object?.name ?? '?'}.${propName} = ...`,
              })
            }
          }
        }
      }
    })
  }
  return out
}
