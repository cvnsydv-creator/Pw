-- CvanshTALKS learning platform schema (Supabase SQL Editor)
-- Run all of this SQL once. It uses RLS and does not allow users to self-assign admin.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'student' check (role in ('student','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.learning_content (
  id uuid primary key default gen_random_uuid(),
  kind text not null check (kind in ('course','lecture','note')),
  title text not null check (char_length(title) between 1 and 140),
  subject text not null,
  description text not null default '',
  url text,
  published boolean not null default false,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  constraint content_url_required check (kind = 'course' or url is not null)
);

alter table public.profiles enable row level security;
alter table public.learning_content enable row level security;

drop policy if exists "Read own profile" on public.profiles;
create policy "Read own profile" on public.profiles
for select to authenticated using (auth.uid() = id);
-- Intentionally no browser-side profile insert/update policy: users cannot promote themselves.

drop policy if exists "Read published content or admin content" on public.learning_content;
create policy "Read published content or admin content" on public.learning_content
for select to anon, authenticated
using (published = true or (auth.uid() is not null and exists (
  select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'
)));

drop policy if exists "Admins insert learning content" on public.learning_content;
create policy "Admins insert learning content" on public.learning_content
for insert to authenticated
with check (auth.uid() = created_by and exists (
  select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'
));

drop policy if exists "Admins update learning content" on public.learning_content;
create policy "Admins update learning content" on public.learning_content
for update to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'))
with check (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));

drop policy if exists "Admins delete learning content" on public.learning_content;
create policy "Admins delete learning content" on public.learning_content
for delete to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.role = 'admin'));

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, email, role)
  values (new.id, new.email, 'student')
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

grant usage on schema public to anon, authenticated;
grant select on public.learning_content to anon, authenticated;
grant insert, update, delete on public.learning_content to authenticated;
grant select on public.profiles to authenticated;

-- After creating and confirming your own website account, run separately:
-- update public.profiles set role = 'admin' where email = 'YOUR-EXACT-EMAIL';
-- Check that exactly one row changed. Never assign admin to other users.
