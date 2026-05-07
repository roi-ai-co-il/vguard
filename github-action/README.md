# Vguard GitHub Action

Run a Vguard security scan on every PR. Posts a comment with the findings table; updates the same comment on subsequent runs (no comment spam).

## Quick start

```yaml
# .github/workflows/security.yml
name: Security
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  vguard:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
      contents: read
    steps:
      # Replace with your own preview-deploy step.
      - id: preview
        run: echo "url=https://your-pr-${{ github.event.pull_request.number }}.vercel.app" >> $GITHUB_OUTPUT

      - uses: roi-ai-co-il/vguard-action@v1
        with:
          url: ${{ steps.preview.outputs.url }}
          fail-on: warn         # critical | warn | info | never
          comment-on-pr: 'true'
```

## Inputs

| Name | Required | Default | Description |
|---|---|---|---|
| `url` | yes | — | Target URL to scan (preview deploy or production). |
| `fail-on` | no | `warn` | Severity floor that fails the action: `critical` / `warn` / `info` / `never`. |
| `comment-on-pr` | no | `true` | Post (and update) a comment on the PR with the findings table. |
| `comment-tag` | no | `vguard` | Hidden marker the action uses to find its existing comment. Change it if you run multiple scans on one PR (e.g. one for staging, one for production). |
| `api-url` | no | `https://vguardus.com` | Override the API base — useful for self-hosted Vguard instances. |

## Outputs

| Name | When | Description |
|---|---|---|
| `vibe-score` | success | Numeric Vibe Score 0–100. |
| `critical` | success | Number of critical findings. |
| `warn` | success | Number of warn findings. |
| `info` | success | Number of info findings. |
| `outcome` | always | `success` / `blocked_by_waf` / `blocked_by_target` / `unreachable` / `timeout` / `internal`. |

## Permissions

For the PR-comment feature, the workflow needs:

```yaml
permissions:
  pull-requests: write
  contents: read
```

This is automatic with the default `GITHUB_TOKEN`.

## What gets scanned

See [the main repo README](../README.md) — same Stage 1 pipeline as `npx vguard scan`.

## License

MIT — built by [ROI AI](https://roiai.co.il) (Roy Argaman, Oded Safdie).
