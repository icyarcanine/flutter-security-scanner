create table posts (
  id uuid primary key,
  user_id uuid not null references auth.users(id),
  title text not null
);

alter table posts enable row level security;

create policy "Users can read their posts"
on posts
for select
using (auth.uid() = user_id);
