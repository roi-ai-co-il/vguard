-- Vguard OAST collaborator — records server-side fetches of our canary URL,
-- which CONFIRMS SSRF on a scanned target. Lives in the roi-ai-internal Supabase
-- project alongside the other `vs_` tables.
--
-- Written by the /api/oast receiver and read by the scanner's SSRF poll, both
-- via the service-role key. RLS is enabled with NO anon/authenticated policies
-- (default-deny for the public; service role bypasses RLS).

create table if not exists public.vs_oast_hits (
  id          bigint generated always as identity primary key,
  token       text not null,
  hit_at      timestamptz not null default now(),
  remote_addr text,
  user_agent  text
);

-- The scanner polls by token within the same scan window.
create index if not exists vs_oast_hits_token_idx on public.vs_oast_hits (token, hit_at desc);

alter table public.vs_oast_hits enable row level security;
-- No policies on purpose: only the service role (receiver + scanner) touches it.
