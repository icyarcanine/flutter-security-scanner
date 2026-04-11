import { Finding } from '../models/finding';
import { ProjectContext } from '../scanner/projectContext';

export enum RuleStage {
  fast = 1,
  ast = 2,
  taint = 3,
}

export interface Rule {
  readonly code: string;
  readonly stage?: RuleStage; // Default is fast
  evaluate(context: ProjectContext): Finding[] | Promise<Finding[]>;
}
