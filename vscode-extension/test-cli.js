"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const scanner_1 = require("./src/scanner/scanner");
const path = __importStar(require("path"));
async function main() {
    const targetDir = process.argv[2];
    if (!targetDir) {
        console.error("Please provide a target directory.");
        process.exit(1);
    }
    const rootPath = path.resolve(targetDir);
    const scanner = new scanner_1.ProjectScanner(true);
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
    }
    catch (err) {
        console.error("Error scanning:", err);
        process.exit(1);
    }
}
main();
