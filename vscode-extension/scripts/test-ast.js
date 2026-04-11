const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { ParserContext } = require('../out/ast/parser');
const { walkAst } = require('../out/ast/traversal');

async function main() {
  console.log("Setting up temporary test file...");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fsh-ast-'));
  const testFile = path.join(root, 'test.js');

  fs.writeFileSync(testFile, `
    function helloWorld() {
      const greeting = "Hello Tree-Sitter";
      console.log(greeting);
    }
  `);
  const dartFile = path.join(root, 'test.dart');
  fs.writeFileSync(dartFile, `
    void helloWorld(String input) {
      final greeting = "Hello $input";
      print(greeting);
    }
  `);

  console.log("Loading ParserContext...");
  const parser = await ParserContext.getParserForFile(testFile);
  assert(parser, "Parser should not be null; WASM should load successfully.");

  console.log("Parsing file...");
  const content = fs.readFileSync(testFile, 'utf8');
  const tree = parser.parse(content);
  assert(tree, "Tree should exist after parsing");

  const rootNode = tree.rootNode;
  assert(rootNode, "Root node should exist");
  assert.strictEqual(rootNode.type, 'program', "Root node type should be 'program'");

  let foundFunction = false;
  let foundString = false;

  console.log("Testing Traversal...");
  walkAst(rootNode, (node) => {
    if (node.type === 'function_declaration') {
      foundFunction = true;
    }
    if (node.type === 'string') {
      foundString = true;
      assert(node.text.includes("Hello Tree-Sitter"), "String text should match AST parsing");
    }
  });

  assert(foundFunction, "Traversal should have found a function_declaration node");
  assert(foundString, "Traversal should have found a string node");

  console.log("Loading Dart ParserContext...");
  const dartParser = await ParserContext.getParserForFile(dartFile);
  assert(dartParser, "Dart parser should not be null; native grammar should load successfully.");

  console.log("Parsing Dart file...");
  const dartContent = fs.readFileSync(dartFile, 'utf8');
  const dartTree = dartParser.parse(dartContent);
  assert(dartTree, "Dart tree should exist after parsing");
  assert.strictEqual(dartTree.rootNode.type, 'program', "Dart root node type should be 'program'");
  assert.strictEqual(dartTree.rootNode.hasError(), false, "Dart parser should parse the smoke file without syntax errors");

  fs.rmSync(root, { recursive: true, force: true });
  console.log("AST Engine Validation Passed! ✔");
}

main().catch(err => {
  console.error("AST validation failed:", err);
  process.exit(1);
});
