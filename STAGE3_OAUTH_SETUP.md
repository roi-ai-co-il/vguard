# Stage 3 — Vercel OAuth Setup (one-time, ~5 min)

The OAuth verification method ("Verify with Vercel" button in the Stage 3 modal) requires a Vercel Integration that Anthropic's API can't create remotely. You do this once via the Vercel UI.

## Steps

1. Open https://vercel.com/dashboard/integrations/console
2. Click **Create Integration** (top right)
3. Fill in:
   - **Name:** `Vguard`
   - **Slug:** `Vguard` (any unique slug — doesn't need to match anything)
   - **Logo:** optional, can skip
   - **Categories:** Security
   - **Description:** `Verify domain ownership for Vguard deep scans.`
   - **Redirect URLs:** `https://vibesecure-tau.vercel.app/api/oauth/vercel/callback`
   - **Configurable URLs:** leave empty
   - **Permissions / Scopes:** check **`read:project`** (lets us list the user's projects + aliases to confirm ownership)
4. Save. You'll land on the integration's settings page.
5. Copy the **Client ID** and **Client Secret** (the secret only shows once — save it).

## Wire to Vercel project

From PowerShell on your machine (since the cowork network blocks Vercel CLI sync from my side):

```powershell
cd "c:\Users\royia\01_Business\my mind\ROI-AI\Vguard"
echo "<CLIENT_ID>" | npx vercel env add VERCEL_OAUTH_CLIENT_ID production
echo "<CLIENT_SECRET>" | npx vercel env add VERCEL_OAUTH_CLIENT_SECRET production
echo "https://vibesecure-tau.vercel.app" | npx vercel env add VGUARD_PUBLIC_ORIGIN production
$env:GIT_CEILING_DIRECTORIES="c:\Users\royia\01_Business\my mind\ROI-AI"
npx vercel deploy --prod --yes
```

After the redeploy, the "Verify with Vercel (OAuth)" button in the Stage 3 modal becomes functional. Click it on the live site → redirects to Vercel for consent → callback verifies that the scanned domain is in one of your projects' aliases → marks ownership as verified in `vs_verified_domains` (30-day TTL).

## Why I can't automate this step

Vercel does not expose an API endpoint to create OAuth Integrations. The `/v1/integrations/configurations` API manages existing integration *installations*, not creation of new OAuth apps. The Integrations Console is UI-only.

## After you've set it up — verify

Replace `<DOMAIN>` with a domain you own that's deployed on Vercel:

```bash
curl -I "https://vibesecure-tau.vercel.app/api/oauth/vercel/start?domain=<DOMAIN>&uuid=vs-test-1234567890123456"
```

Expected: `302 Found` with `Location:` header pointing to `https://vercel.com/oauth/authorize?...`. If it returns `503 Vercel OAuth is not configured`, the env vars didn't take effect — re-run `vercel env add` and redeploy.

## Status

🔴 Pending Royi — UI-only step, ~5 minutes.
