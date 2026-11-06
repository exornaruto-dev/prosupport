-- P PRO SUPPORT - Employee Attendance System
-- Supabase SQL setup (run once in Supabase Dashboard > SQL Editor)
-- This creates the database structure and security policies.
-- It does NOT migrate existing browser localStorage records or connect the HTML app automatically.

create extension if not exists pgcrypto;

-- 1) Employee profiles (linked to Supabase Auth users)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  employee_code text unique,
  full_name text not null default '',
  role text not null default 'employee' check (role in ('admin','employee')),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Create a profile automatically when a user signs up through Supabase Auth.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, employee_code, full_name, role)
  values (
    new.id,
    nullif(new.raw_user_meta_data->>'employee_code',''),
    coalesce(nullif(new.raw_user_meta_data->>'full_name',''), split_part(new.email,'@',1)),
    'employee'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Helper function used by Row Level Security policies.
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin' and p.is_active = true
  );
$$;

-- 2) Attendance: one row per employee per work date.
create table if not exists public.attendance (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.profiles(id) on delete restrict,
  work_date date not null,
  check_in timestamptz,
  check_out timestamptz,
  note text,
  last_edited_at timestamptz,
  last_edited_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(employee_id, work_date),
  check (check_out is null or check_in is null or check_out >= check_in)
);
create index if not exists attendance_work_date_idx on public.attendance(work_date desc);
create index if not exists attendance_employee_date_idx on public.attendance(employee_id, work_date desc);

-- 3) Leave requests. Store attachment files in the private Storage bucket below;
-- save the resulting object path in attachment_path (not the file's base64 data).
create table if not exists public.leave_requests (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.profiles(id) on delete restrict,
  leave_type text not null check (leave_type in ('ลาป่วย','ลากิจ','sick','personal')),
  start_date date not null,
  end_date date not null,
  reason text not null,
  attachment_path text,
  attachment_name text,
  attachment_mime_type text,
  status text not null default 'รออนุมัติ' check (status in ('รออนุมัติ','อนุมัติ','ไม่อนุมัติ','pending','approved','rejected')),
  reviewed_by uuid references public.profiles(id) on delete set null,
  reviewed_at timestamptz,
  review_note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (end_date >= start_date)
);
create index if not exists leave_requests_employee_idx on public.leave_requests(employee_id, created_at desc);
create index if not exists leave_requests_status_idx on public.leave_requests(status, created_at desc);

-- 4) Requests to correct an attendance time.
create table if not exists public.attendance_correction_requests (
  id uuid primary key default gen_random_uuid(),
  employee_id uuid not null references public.profiles(id) on delete restrict,
  work_date date not null,
  field text not null check (field in ('checkIn','checkOut','check_in','check_out')),
  requested_time time not null,
  reason text not null,
  status text not null default 'รออนุมัติ' check (status in ('รออนุมัติ','อนุมัติ','ไม่อนุมัติ','pending','approved','rejected')),
  reviewed_by uuid references public.profiles(id) on delete set null,
  reviewed_at timestamptz,
  applied_at timestamptz,
  review_note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists correction_employee_idx on public.attendance_correction_requests(employee_id, work_date desc);
create index if not exists correction_status_idx on public.attendance_correction_requests(status, created_at desc);

-- 5) Work calendar (Sunday defaults can be rendered by the app; explicit exceptions go here).
create table if not exists public.work_calendar (
  work_date date primary key,
  day_type text not null check (day_type in ('workday','holiday')),
  note text,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 6) Shared application settings, including start/end of lunch break.
create table if not exists public.app_settings (
  setting_key text primary key,
  setting_value jsonb not null,
  updated_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now()
);
insert into public.app_settings(setting_key, setting_value)
values
  ('attendance', '{"start":"08:30","grace":5}'::jsonb),
  ('lunch_break', '{"start":"12:00","end":"13:00"}'::jsonb)
on conflict (setting_key) do nothing;

-- Generic updated_at trigger.
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

do $$
declare t text;
begin
  foreach t in array array['profiles','attendance','leave_requests','attendance_correction_requests','work_calendar','app_settings'] loop
    execute format('drop trigger if exists set_updated_at on public.%I', t);
    execute format('create trigger set_updated_at before update on public.%I for each row execute procedure public.set_updated_at()', t);
  end loop;
end $$;

-- Enable RLS on all application tables.
alter table public.profiles enable row level security;
alter table public.attendance enable row level security;
alter table public.leave_requests enable row level security;
alter table public.attendance_correction_requests enable row level security;
alter table public.work_calendar enable row level security;
alter table public.app_settings enable row level security;

-- Profiles: employees see their own profile; admins can see/manage all profiles.
drop policy if exists profiles_select_self_or_admin on public.profiles;
create policy profiles_select_self_or_admin on public.profiles for select to authenticated
using (id = auth.uid() or public.is_admin());
drop policy if exists profiles_update_self_or_admin on public.profiles;
create policy profiles_update_self_or_admin on public.profiles for update to authenticated
using (id = auth.uid() or public.is_admin())
with check (id = auth.uid() or public.is_admin());

-- Attendance: employees read/create/update their own; admins read/manage all.
drop policy if exists attendance_select_self_or_admin on public.attendance;
create policy attendance_select_self_or_admin on public.attendance for select to authenticated
using (employee_id = auth.uid() or public.is_admin());
drop policy if exists attendance_insert_self_or_admin on public.attendance;
create policy attendance_insert_self_or_admin on public.attendance for insert to authenticated
with check (employee_id = auth.uid() or public.is_admin());
drop policy if exists attendance_update_self_or_admin on public.attendance;
create policy attendance_update_self_or_admin on public.attendance for update to authenticated
using (employee_id = auth.uid() or public.is_admin())
with check (employee_id = auth.uid() or public.is_admin());
drop policy if exists attendance_delete_admin on public.attendance;
create policy attendance_delete_admin on public.attendance for delete to authenticated
using (public.is_admin());

-- Leave requests: employees create/read their own; admins read/review all.
drop policy if exists leave_select_self_or_admin on public.leave_requests;
create policy leave_select_self_or_admin on public.leave_requests for select to authenticated
using (employee_id = auth.uid() or public.is_admin());
drop policy if exists leave_insert_self on public.leave_requests;
create policy leave_insert_self on public.leave_requests for insert to authenticated
with check (employee_id = auth.uid());
drop policy if exists leave_update_admin on public.leave_requests;
create policy leave_update_admin on public.leave_requests for update to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Correction requests: employees create/read their own; admins read/review all.
drop policy if exists correction_select_self_or_admin on public.attendance_correction_requests;
create policy correction_select_self_or_admin on public.attendance_correction_requests for select to authenticated
using (employee_id = auth.uid() or public.is_admin());
drop policy if exists correction_insert_self on public.attendance_correction_requests;
create policy correction_insert_self on public.attendance_correction_requests for insert to authenticated
with check (employee_id = auth.uid());
drop policy if exists correction_update_admin on public.attendance_correction_requests;
create policy correction_update_admin on public.attendance_correction_requests for update to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Calendar: all signed-in users can view; only admins can edit.
drop policy if exists calendar_select_authenticated on public.work_calendar;
create policy calendar_select_authenticated on public.work_calendar for select to authenticated using (true);
drop policy if exists calendar_admin_all on public.work_calendar;
create policy calendar_admin_all on public.work_calendar for all to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Settings: all signed-in users can read shared settings; only admins can change them.
drop policy if exists settings_select_authenticated on public.app_settings;
create policy settings_select_authenticated on public.app_settings for select to authenticated using (true);
drop policy if exists settings_admin_all on public.app_settings;
create policy settings_admin_all on public.app_settings for all to authenticated
using (public.is_admin()) with check (public.is_admin());

-- Private bucket for leave attachments (PDF/JPG/PNG, app should enforce 2 MB max).
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('leave-attachments','leave-attachments',false,2097152,array['application/pdf','image/jpeg','image/png'])
on conflict (id) do update set public = false, file_size_limit = 2097152,
  allowed_mime_types = array['application/pdf','image/jpeg','image/png'];

drop policy if exists leave_files_select_own_or_admin on storage.objects;
create policy leave_files_select_own_or_admin on storage.objects for select to authenticated
using (bucket_id = 'leave-attachments' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));
drop policy if exists leave_files_insert_own on storage.objects;
create policy leave_files_insert_own on storage.objects for insert to authenticated
with check (bucket_id = 'leave-attachments' and (storage.foldername(name))[1] = auth.uid()::text);
drop policy if exists leave_files_update_own_or_admin on storage.objects;
create policy leave_files_update_own_or_admin on storage.objects for update to authenticated
using (bucket_id = 'leave-attachments' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()))
with check (bucket_id = 'leave-attachments' and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));
drop policy if exists leave_files_delete_admin on storage.objects;
create policy leave_files_delete_admin on storage.objects for delete to authenticated
using (bucket_id = 'leave-attachments' and public.is_admin());

-- IMPORTANT ADMIN SETUP:
-- 1. Create your first user in Authentication > Users.
-- 2. Find that user's UUID, then run the statement below after replacing the UUID:
-- update public.profiles set role = 'admin' where id = 'PASTE-AUTH-USER-UUID-HERE';
-- 3. Add employee users through Supabase Auth. Their profiles are created automatically.
-- 4. Set employee_code/full_name in public.profiles after signup.
-- 5. Never put the Supabase service_role key in browser JavaScript.
-- Run AFTER PProSupport_Supabase_Setup.sql in Supabase SQL Editor.
-- Cloud RPCs for secure employee attendance. All times are generated by the database.

-- Prevent employees from changing their own role or activation state.
drop policy if exists profiles_update_self_or_admin on public.profiles;
create policy profiles_update_self_or_admin on public.profiles
for update to authenticated
using (id = auth.uid() or public.is_admin())
with check (
  public.is_admin()
  or (id = auth.uid() and role = 'employee' and is_active = true)
);

create or replace function public.employee_check_in()
returns public.attendance
language plpgsql
security definer
set search_path = public
as $$
declare result public.attendance;
begin
  if auth.uid() is null then raise exception 'กรุณาเข้าสู่ระบบ'; end if;
  if not exists(select 1 from public.profiles where id=auth.uid() and role='employee' and is_active=true) then
    raise exception 'บัญชีนี้ไม่มีสิทธิ์ลงเวลา';
  end if;
  insert into public.attendance(employee_id,work_date,check_in)
  values(auth.uid(),(now() at time zone 'Asia/Bangkok')::date,now())
  returning * into result;
  return result;
exception when unique_violation then
  raise exception 'วันนี้ลงเวลาเข้างานแล้ว';
end;
$$;

create or replace function public.employee_check_out()
returns public.attendance
language plpgsql
security definer
set search_path = public
as $$
declare result public.attendance;
begin
  if auth.uid() is null then raise exception 'กรุณาเข้าสู่ระบบ'; end if;
  update public.attendance
  set check_out=now()
  where employee_id=auth.uid()
    and work_date=(now() at time zone 'Asia/Bangkok')::date
    and check_in is not null and check_out is null
  returning * into result;
  if result.id is null then raise exception 'ไม่พบรายการเข้างานวันนี้ หรือบันทึกเวลาออกแล้ว'; end if;
  return result;
end;
$$;

revoke all on function public.employee_check_in() from public;
revoke all on function public.employee_check_out() from public;
grant execute on function public.employee_check_in() to authenticated;
grant execute on function public.employee_check_out() to authenticated;

-- Storage: allow the owner and admins to read attachments; employees may upload only to own folder.
drop policy if exists leave_files_select_own_or_admin on storage.objects;
create policy leave_files_select_own_or_admin on storage.objects for select to authenticated
using (bucket_id='leave-attachments' and ((storage.foldername(name))[1]=auth.uid()::text or public.is_admin()));
