void main() {
  // A. Nested parentheses
  print(getToken(user.getSession()));

  // B. Parentheses inside strings
  print("token value ) still inside string");

  // C. Escaped quotes
  print("token: \"secret\"");

  // D. Multi-line with strings
  print(
    "value: $accessToken"
  );

  // E. Broken syntax (must NOT crash)
  print(
    accessToken
}
