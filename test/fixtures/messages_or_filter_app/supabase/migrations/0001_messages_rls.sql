alter table messages enable row level security;

create policy "Users can read their messages"
on messages
for select
using (auth.uid() = sender_id OR auth.uid() = receiver_id);
