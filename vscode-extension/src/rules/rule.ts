import { Finding } from '../models/finding';
import { ProjectContext } from '../scanner/projectContext';

export enum RuleStage {
  /** Pure regex / heuristic — runs on every file, no AST. */
  fast = 1,
  /** Structural AST patterns — requires the file's tree-sitter AST. */
  ast = 2,
  /** Source-to-sink data-flow / taint analysis. */
  taint = 3,
}

/**
 * Every rule must explicitly declare a stage so the scheduler can run them
 * in deterministic order (fast → ast → taint) and so the precision-self-test
 * can reason about which stage produced a finding. Defaulting was a footgun
 * that hid mis-staged rules; making it required catches the omission at
 * compile time.
 */
export interface Rule {
  readonly code: string;
  readonly stage: RuleStage;
  evaluate(context: ProjectContext): Finding[] | Promise<Finding[]>;
}
