import 'package:webview_flutter/webview_flutter.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

void createWebView(String userInput) {
  final controller = WebViewController()
    ..setJavaScriptMode(JavaScriptMode.unrestricted)
    ..loadRequest(Uri.parse('https://example.com'));

  // Direct javascript: URI — XSS sink that should fire even with a literal.
  controller.loadUrl("javascript:alert('hi')");

  // Dynamic JS execution: user input interpolated into the script body.
  controller.runJavaScript("document.title = '$userInput'");
  controller.runJavaScriptReturningResult('alert("' + userInput + '")');

  // Dynamic HTML page where the body sees attacker-controlled values.
  controller.loadHtmlString('<h1>$userInput</h1>');
}
