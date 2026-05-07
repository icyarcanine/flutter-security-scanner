import 'package:analyzer/dart/ast/ast.dart';
import 'package:analyzer/dart/ast/visitor.dart';

class TaintState {
  TaintState({Set<String>? tainted}) : tainted = tainted ?? {};
  
  final Set<String> tainted;
  
  TaintState clone() {
    return TaintState(tainted: Set.of(tainted));
  }
}

enum SinkKind { sql, command, xss, eval }

class TaintFinding {
  TaintFinding({
    required this.node,
    required this.sinkName,
    required this.sinkKind,
    required this.confidence,
  });

  final AstNode node;
  final String sinkName;
  final SinkKind sinkKind;
  final String confidence; // 'high' or 'medium'
}

class TaintTracker extends RecursiveAstVisitor<void> {
  final List<TaintFinding> findings = [];
  TaintState _state = TaintState();

  @override
  void visitMethodDeclaration(MethodDeclaration node) {
    _analyzeFunction(node.parameters, node.body);
  }

  @override
  void visitFunctionDeclaration(FunctionDeclaration node) {
    _analyzeFunction(node.functionExpression.parameters, node.functionExpression.body);
  }
  
  void _analyzeFunction(FormalParameterList? parameters, FunctionBody? body) {
    if (body == null) return;
    
    final oldState = _state;
    _state = _state.clone();
    
    if (parameters != null) {
      for (final param in parameters.parameters) {
        final name = param.name?.lexeme;
        if (name != null) {
          _state.tainted.add(name);
        }
      }
    }
    
    body.accept(this);
    
    _state = oldState;
  }

  @override
  void visitVariableDeclaration(VariableDeclaration node) {
    super.visitVariableDeclaration(node);
    
    final initializer = node.initializer;
    final name = node.name.lexeme;
    
    if (initializer != null && _isTainted(initializer) && !_isSanitized(initializer)) {
      _state.tainted.add(name);
    } else {
      _state.tainted.remove(name);
    }
  }

  @override
  void visitAssignmentExpression(AssignmentExpression node) {
    super.visitAssignmentExpression(node);
    
    final left = node.leftHandSide;
    final right = node.rightHandSide;
    
    if (left is SimpleIdentifier) {
      final name = left.name;
      if (node.operator.type.lexeme == '=') {
        if (_isTainted(right) && !_isSanitized(right)) {
          _state.tainted.add(name);
        } else {
          _state.tainted.remove(name);
        }
      } else {
        if (_isTainted(right) && !_isSanitized(right)) {
          _state.tainted.add(name);
        }
      }
    }
  }

  bool _isTainted(Expression node) {
    if (node is SimpleIdentifier) {
      return _state.tainted.contains(node.name);
    } else if (node is StringInterpolation) {
      for (final el in node.elements) {
        if (el is InterpolationExpression && _isTainted(el.expression)) {
          return true;
        }
      }
      return false;
    } else if (node is BinaryExpression) {
      return _isTainted(node.leftOperand) || _isTainted(node.rightOperand);
    } else if (node is ParenthesizedExpression) {
      return _isTainted(node.expression);
    } else if (node is MethodInvocation) {
      final target = node.target;
      if (target != null && _isTainted(target)) return true;
    } else if (node is PropertyAccess) {
      final target = node.target;
      if (target != null && _isTainted(target)) return true;
    } else if (node is PrefixedIdentifier) {
      if (_state.tainted.contains(node.prefix.name)) return true;
      if (_state.tainted.contains(node.identifier.name)) return true;
    } else if (node is ListLiteral) {
      for (final el in node.elements) {
        if (el is Expression && _isTainted(el)) return true;
      }
    }
    return false;
  }

  @override
  void visitMethodInvocation(MethodInvocation node) {
    super.visitMethodInvocation(node);
    final methodName = node.methodName.name;
    final targetName = node.target?.toSource();
    
    if (['query', 'rawQuery', 'execute', 'rawExecute', 'rawInsert', 'rawUpdate', 'rawDelete'].contains(methodName)) {
      bool isLikelySql = false;
      if (['rawQuery', 'rawExecute', 'rawInsert', 'rawUpdate', 'rawDelete'].contains(methodName)) {
        isLikelySql = true;
      }
      if (!isLikelySql && targetName != null) {
        final t = targetName.toLowerCase();
        if (t.contains('db') || t.contains('database') || t.contains('sqlite') || t.contains('conn') || t.contains('batch') || t.contains('txn') || t.contains('client')) {
          isLikelySql = true;
        }
      }
      
      final args = node.argumentList.arguments;
      
      if (!isLikelySql && args.isNotEmpty) {
        final arg = args.first;
        if (arg is StringLiteral) {
          final val = arg.stringValue?.toUpperCase() ?? '';
          if (val.contains('SELECT ') || val.contains('INSERT ') || val.contains('UPDATE ') || val.contains('DELETE ') || val.contains('CREATE ') || val.contains('DROP ') || val.contains('ALTER ')) {
            isLikelySql = true;
          }
        } else if (arg is StringInterpolation) {
           for (final el in arg.elements) {
             if (el is InterpolationString) {
                final val = el.value.toUpperCase();
                if (val.contains('SELECT ') || val.contains('INSERT ') || val.contains('UPDATE ') || val.contains('DELETE ') || val.contains('CREATE ') || val.contains('DROP ') || val.contains('ALTER ')) {
                  isLikelySql = true;
                  break;
                }
             }
           }
        } else if (arg is SimpleIdentifier && _state.tainted.contains(arg.name)) {
           // If it's a tainted variable, we might not know if it's SQL.
           // But if methodName is query or execute, and target doesn't look like DB, it's probably not DB.
        }
      }

      if (isLikelySql && args.isNotEmpty) {
        final arg = args.first;
        if (_isTainted(arg)) {
          findings.add(TaintFinding(node: node, sinkName: methodName, sinkKind: SinkKind.sql, confidence: 'high'));
        } else if (_isDynamicString(arg)) {
          findings.add(TaintFinding(node: node, sinkName: methodName, sinkKind: SinkKind.sql, confidence: 'medium'));
        }
      }
    } else if ((targetName == 'Process' || targetName == 'io.Process') && ['run', 'start'].contains(methodName)) {
      final args = node.argumentList.arguments;
      if (args.length >= 2) {
        final exe = args[0];
        final cmdArgs = args[1];
        if (_isTainted(exe) || _isTainted(cmdArgs)) {
          findings.add(TaintFinding(node: node, sinkName: methodName, sinkKind: SinkKind.command, confidence: 'high'));
        } else if (_isDynamicString(exe) || _isDynamicString(cmdArgs)) {
          findings.add(TaintFinding(node: node, sinkName: methodName, sinkKind: SinkKind.command, confidence: 'medium'));
        }
      } else if (args.isNotEmpty) {
        if (_isTainted(args[0])) {
          findings.add(TaintFinding(node: node, sinkName: methodName, sinkKind: SinkKind.command, confidence: 'high'));
        }
      }
    } else if (methodName == 'Html' || methodName == 'Markdown' || methodName == 'HtmlElementView') {
      for (final arg in node.argumentList.arguments) {
        if (arg is NamedExpression && arg.name.label.name == 'data') {
          final expr = arg.expression;
          if (_isSanitized(expr)) return;
          
          if (_isTainted(expr)) {
            findings.add(TaintFinding(node: node, sinkName: methodName, sinkKind: SinkKind.xss, confidence: 'high'));
          } else if (_isDynamicString(expr)) {
            findings.add(TaintFinding(node: node, sinkName: methodName, sinkKind: SinkKind.xss, confidence: 'medium'));
          }
        }
      }
    }
  }

  @override
  void visitPropertyAccess(PropertyAccess node) {
    super.visitPropertyAccess(node);
    _checkXssAssignment(node.propertyName.name, node, node.parent);
  }
  
  @override
  void visitPrefixedIdentifier(PrefixedIdentifier node) {
    super.visitPrefixedIdentifier(node);
    _checkXssAssignment(node.identifier.name, node, node.parent);
  }

  void _checkXssAssignment(String propertyName, AstNode node, AstNode? parent) {
    if (['innerHTML', 'outerHTML'].contains(propertyName)) {
      if (parent is AssignmentExpression && parent.leftHandSide == node) {
        final right = parent.rightHandSide;
        if (_isSanitized(right)) return;
        
        if (_isTainted(right)) {
          findings.add(TaintFinding(node: parent, sinkName: propertyName, sinkKind: SinkKind.xss, confidence: 'high'));
        } else if (_isDynamicString(right)) {
          findings.add(TaintFinding(node: parent, sinkName: propertyName, sinkKind: SinkKind.xss, confidence: 'medium'));
        }
      }
    }
  }

  @override
  void visitInstanceCreationExpression(InstanceCreationExpression node) {
    super.visitInstanceCreationExpression(node);
    final typeName = node.constructorName.type.toSource();
    
    if (typeName.contains('Html') || typeName.contains('Markdown') || typeName.contains('HtmlElementView')) {
      for (final arg in node.argumentList.arguments) {
        if (arg is NamedExpression && arg.name.label.name == 'data') {
          final expr = arg.expression;
          if (_isSanitized(expr)) return;
          
          if (_isTainted(expr)) {
            findings.add(TaintFinding(node: node, sinkName: typeName, sinkKind: SinkKind.xss, confidence: 'high'));
          } else if (_isDynamicString(expr)) {
            findings.add(TaintFinding(node: node, sinkName: typeName, sinkKind: SinkKind.xss, confidence: 'medium'));
          }
        } else if (arg is NamedExpression && arg.name.label.name == 'viewType') {
           final expr = arg.expression;
          if (_isSanitized(expr)) return;
          
          if (_isTainted(expr)) {
            findings.add(TaintFinding(node: node, sinkName: typeName, sinkKind: SinkKind.xss, confidence: 'high'));
          } else if (_isDynamicString(expr)) {
            findings.add(TaintFinding(node: node, sinkName: typeName, sinkKind: SinkKind.xss, confidence: 'medium'));
          }
        }
      }
    }
  }

  bool _isSanitized(Expression node) {
    if (node is MethodInvocation) {
      final name = node.methodName.name.toLowerCase();
      if (name.contains('replaceall') || name.contains('sanitize') || name.contains('escape')) {
        return true;
      }
      final target = node.target;
      if (target != null && _isSanitized(target)) return true;
    }
    return false;
  }

  bool _isDynamicString(Expression node) {
    if (node is StringInterpolation) return true;
    if (node is BinaryExpression && (node.operator.type.lexeme == '+') && 
       (node.leftOperand is StringLiteral || node.rightOperand is StringLiteral)) {
      return true;
    }
    if (node is ListLiteral) {
      for (final el in node.elements) {
        if (el is Expression && _isDynamicString(el)) return true;
      }
    }
    if (node is SimpleIdentifier && _state.tainted.contains(node.name)) {
      return true;
    }
    return false;
  }
}
