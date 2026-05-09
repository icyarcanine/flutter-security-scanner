//! Temporary debug utility to inspect tree-sitter-dart AST structure.

#[test]
fn debug_tree_structure() {
    use tree_sitter::{Language, Parser};
    let mut parser = Parser::new();
    let language: Language = tree_sitter_dart::language();
    parser.set_language(&language).unwrap();

    let source = r#"
import 'package:sqflite/sqflite.dart';

void sqlInjectionTests(Database db, String userInput) {
  db.rawQuery("SELECT * FROM users WHERE id = $userInput");
}
"#;

    let tree = parser.parse(source, None).unwrap();

    fn print_tree(node: tree_sitter::Node, source: &str, depth: usize) {
        let indent = "  ".repeat(depth);
        let text = &source[node.start_byte()..node.end_byte().min(source.len())];
        let text_preview = if text.len() > 30 { &text[..30] } else { text };
        println!(
            "{}{} [{}..{}] id={} {:?}",
            indent,
            node.kind(),
            node.start_byte(),
            node.end_byte(),
            node.id(),
            text_preview.replace('\n', "\\n")
        );
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.is_named() {
                print_tree(child, source, depth + 1);
            }
        }
    }

    print_tree(tree.root_node(), source, 0);
}
