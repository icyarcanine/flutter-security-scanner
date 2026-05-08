create or replace function admin_delete_user(target uuid)
returns void
language plpgsql
security definer
as $$
begin
  delete from profiles where id = target;
end;
$$;

create or replace function safe_user_summary()
returns json
language sql
security definer
as $$
  select json_build_object('user_id', auth.uid());
$$;
