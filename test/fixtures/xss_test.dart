import 'dart:html';
import 'package:flutter/material.dart';
import 'package:flutter_html/flutter_html.dart';

void xssTests(String userInput) {
  // Scenario 1: Vulnerable - innerHTML (Expected: Catch)
  final div = DivElement();
  div.innerHTML = userInput;

  // Scenario 2: Vulnerable - outerHTML (Expected: Catch)
  div.outerHTML = "<div>" + userInput + "</div>";

  // Scenario 3: Safe - textContent (Expected: Safe)
  div.textContent = userInput;

  // Scenario 4: Vulnerable - Html widget with dynamic data (Expected: Catch)
  final widget = Html(data: userInput);

  // Scenario 5: Safe - Escaped HTML (Expected: Catch - False Positive if scanner doesn't track sanitization)
  final escapedInput = userInput.replaceAll('<', '&lt;');
  div.innerHTML = escapedInput;

  // Scenario 6: Blindspot - Method alias (Expected: Miss)
  final alias = div.innerHtml; // Not an assignment
}
