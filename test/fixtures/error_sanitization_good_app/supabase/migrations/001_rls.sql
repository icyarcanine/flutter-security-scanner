ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY users_insert_policy ON users FOR INSERT USING (auth.uid() = id);
