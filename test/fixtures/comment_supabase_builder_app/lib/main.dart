// Supabase-style API, but not actually Supabase.
class FakeApi {
  FakeApi from(String table) => this;
  FakeApi select() => this;
}

void main() {
  final api = FakeApi();
  api.from('posts').select();
}
