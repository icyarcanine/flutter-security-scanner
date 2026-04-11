create table audit_log (
  id uuid primary key,
  actor_id uuid not null
);
