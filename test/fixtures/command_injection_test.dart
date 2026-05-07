import 'dart:io';

void commandInjectionTests(String userInput) {
  // Scenario 1: Vulnerable - String interpolation in process.run (Expected: Catch)
  Process.run('echo', ['$userInput']);

  // Scenario 2: Vulnerable - String concat in process.start (Expected: Catch)
  Process.start('ls -l ' + userInput, []);

  // Scenario 3: Safe - Fixed array arguments (Expected: Safe, but regex might FP if args contain '$')
  final fixedArg = '\$HOME';
  Process.run('ls', ['-l', fixedArg]);

  // Scenario 4: Blindspot - Variable passing without interpolation in call (Expected: Miss)
  final cmd = 'cat $userInput';
  Process.run(cmd, []);
}
