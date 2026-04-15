import 'package:webview_flutter/webview_flutter.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

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

  // JavaScriptChannel registered without any NavigationDelegate in this
  // file — no origin gate, bridge inherited on redirect.
  controller.addJavaScriptChannel(
    JavaScriptChannel(name: 'NativeBridge', onMessageReceived: (m) {}),
  );
}

// Android inappwebview with the deeper Android surface enabled.
final _androidSettings = InAppWebViewSettings(
  javaScriptEnabled: true,
  allowContentAccess: true,
  allowUniversalAccessFromFileURLs: true,
  allowFileAccessFromFileURLs: true,
  mixedContentMode: MixedContentMode.alwaysAllow,
);
