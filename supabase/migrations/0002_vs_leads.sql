-- Vguard unified lead inbox. Captures every inbound lead so Royi + Oded can see
-- them in the admin dashboard (the contact form previously only emailed, and the
-- Stage-3 verify flow collected an email but never stored it — both are leads).
--
-- Two sources:
--   source = 'contact'  → homepage contact form (name + email + message)
--   source = 'verify'   → Stage-3 ownership-verification email (domain owner
--                          intent — the hottest lead). `domain`/`method`/`verified`
--                          describe the verification attempt.
--
-- Written by /api/contact + /api/verify via the service-role key, read by
-- /api/admin/dashboard. RLS on with NO anon/authenticated policies
-- (default-deny for the public; service role bypasses RLS). Same pattern as
-- vs_oast_hits / vs_scan_log.

create table if not exists public.vs_leads (
  id          bigint generated always as identity primary key,
  created_at  timestamptz not null default now(),
  source      text        not null,                       -- 'contact' | 'verify'
  name        text,
  email       text        not null,
  message     text,
  domain      text,                                        -- verify: scanned domain
  method      text,                                        -- verify: file|dns|vercel
  verified    boolean,                                     -- verify: outcome
  ip_hash     text,                                        -- salted sha256, never raw IP
  user_agent  text,
  status      text        not null default 'new',          -- new|read|replied|archived
  metadata    jsonb       not null default '{}'::jsonb
);

create index if not exists vs_leads_created_idx on public.vs_leads (created_at desc);
create index if not exists vs_leads_status_idx  on public.vs_leads (status);
create index if not exists vs_leads_source_idx  on public.vs_leads (source);

alter table public.vs_leads enable row level security;
-- No policies on purpose: only the service role (API writers + admin reader) touches it.
