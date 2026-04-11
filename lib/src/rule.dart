import 'models/finding.dart';
import 'models/project_context.dart';

abstract class Rule {
  const Rule();

  String get code;

  List<Finding> evaluate(ProjectContext context);
}
