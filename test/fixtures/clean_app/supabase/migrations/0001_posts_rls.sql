alter table posts enable row level security;

create policy "Users can read their posts"
on posts
for select
using (auth.uid() = user_id);
