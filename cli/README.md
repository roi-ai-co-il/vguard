# vguard

Security scanner for vibe-coded apps. Scans a URL, returns findings with paste-ready fix prompts.

```bash
npx vguard scan https://your-app.vercel.app
```

## Install

Run on demand without installing:

```bash
npx vguard scan <url>
```

Or install globally:

```bash
npm install -g vguard
vguard scan <url>
```

## Usage

```bash
vguard scan <url> [options]
vguard <url>                    # shorthand

Options:
  --json          Raw ScanResponse JSON (machine-readable)
  --exit-code     Exit 1 if any critical/warn findings (use in CI)
  --prompt        Print the full fix prompt for every finding
  --prompt=<id>   Print the fix prompt for a specific finding
```

## CI gate

Block merges when the scan finds anything actionable:

```yaml
# .github/workflows/security.yml
- name: Vguard
  run: npx vguard scan ${{ env.PREVIEW_URL }} --exit-code
```

## Pipe to an LLM

Feed the JSON output to your AI agent of choice:

```bash
vguard scan https://app.example.com --json | jq '.findings[] | select(.severity == "critical")'
```

## What gets scanned

Stage 1 (this CLI):

- HTTPS / TLS / cert
- Security headers (CSP / HSTS / X-Frame-Options / COOP / COEP / CORP / …)
- JS bundle inspection (secrets, source maps, npm CVEs)
- Supabase / Firebase / S3 detection
- DNS records (DNSSEC / CAA / DMARC / SPF / DKIM)
- Forms + endpoints discovery
- Active probes: Open Redirect canary, reflected XSS canary, SQLi error-based

Stage 2 (browser-assisted) and Stage 3 (verified deep scan) live on the web UI: <https://vguards.com>.

## Environment

```
VGUARD_API=<url>   Override API base (default: https://vguards.com)
NO_COLOR=1         Disable ANSI color output
```

## License

MIT — built by [ROI AI](https://roiai.co.il) (Royi Argaman, Oded Safdie).
