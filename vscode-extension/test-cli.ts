import { ProjectScanner } from './src/scanner/scanner';
import * as path from 'path';

async function main() {
  const targetDir = process.argv[2];
  if (!targetDir) {
    console.error("Please provide a target directory.");
    process.exit(1);
  }

  const rootPath = path.resolve(targetDir);
  const scanner = new ProjectScanner(true);

  try {
    const report = await scanner.scan(rootPath);
    console.log(JSON.stringify({
      target: rootPath,
      issueCount: report.issueCount,
      suggestionCount: report.suggestionCount,
      findings: report.findings.map(f => ({
        severity: f.severity,
        category: f.category,
        confidence: f.confidence,
        code: f.code,
        message: f.message,
        filePath: f.filePath,
        line: f.line,
        isSuggestion: f.isSuggestion
      }))
    }, null, 2));
  } catch (err) {
    console.error("Error scanning:", err);
    process.exit(1);
  }
}

main();
