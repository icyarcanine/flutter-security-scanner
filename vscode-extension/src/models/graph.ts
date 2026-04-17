/**
 * Code Property Graph (CPG) for the IFDS taint engine.
 *
 * Nodes are CFG statements. Edges are CFG (intra-procedural successors) and
 * ICFG (call/return). A side-table of Statement payloads tells the IFDS flow
 * functions what each node does (assign, call, return, source, sink, sanitize).
 */

export enum NodeKind {
  Unknown,
  Module,
  ClassDecl,
  MethodDecl,
  Block,
  ExprStmt,
  IfStmt,
  ForStmt,
  WhileStmt,
  ReturnStmt,
  Assign,
  Call,
  MethodCall,
  ConstructorCall,
  Identifier,
  Literal,
  Param,
  // Solver Anchors
  EntryNode,
  ExitNode,
  CallSite,
  ReturnSite,
}

export enum EdgeKindTag {
  Ast = 'Ast',
  Cfg = 'Cfg',
  Icfg = 'Icfg',
  Pdg = 'Pdg',
  Sdg = 'Sdg',
  Rdg = 'Rdg',
  /** Callee-entry → call-site return-site, kept so the solver can find matching returns. */
  IcfgReturn = 'IcfgReturn',
}

export interface Node {
  id: number;
  kind: NodeKind;
  fileId: number;
  range: [number, number];
  line?: number;
  symbol?: string;
  procedure?: number; // procedure id this node belongs to
}

export interface Edge {
  src: number;
  dst: number;
  tag: EdgeKindTag;
  metadata?: any;
}

/**
 * Abstract location in the IFDS domain. Locations are variable-level, scoped
 * to a procedure. Fields are modeled as (proc=-1, name='field.x') — good enough
 * for the fixtures we target; a real engine would carry receiver objects.
 */
export interface Loc {
  proc: number;
  name: string;
}

export function locKey(l: Loc): string {
  return `${l.proc}::${l.name}`;
}

export function locEq(a: Loc, b: Loc): boolean {
  return a.proc === b.proc && a.name === b.name;
}

/**
 * Statement payload attached to a CFG node. The IFDS flow functions interpret
 * these to decide which facts are gen'd / killed across each edge.
 */
export type Statement =
  | { kind: 'entry'; proc: number; params: Loc[] }
  | { kind: 'exit'; proc: number }
  | { kind: 'assign'; lhs: Loc; rhs: Rhs }
  /** A call-site node. The matching ReturnSite node holds the ret location. */
  | { kind: 'call'; callee: string; calleeProc?: number; args: Loc[]; returnSite: number }
  | { kind: 'returnSite'; callee: string; calleeProc?: number; ret?: Loc; args: Loc[] }
  | { kind: 'return'; value?: Loc }
  /** Taint source — creates taint on `lhs` unconditionally. */
  | { kind: 'source'; lhs: Loc; label: string }
  /** Sanitizer — killing assignment to `lhs`. */
  | { kind: 'sanitize'; lhs: Loc }
  /** Sink — reports a finding if any of `args` is tainted at this node. */
  | { kind: 'sink'; name: string; args: Loc[]; line: number }
  | { kind: 'noop' };

export type Rhs =
  | { kind: 'var'; loc: Loc }
  | { kind: 'const' }
  | { kind: 'compose'; parts: Loc[] };

export interface Procedure {
  id: number;
  name: string;
  entry: number; // node id
  exit: number;  // node id
  params: Loc[];
  fileId: number;
  /** Line of the procedure header. */
  line: number;
}

export class CodeGraph {
  public nodes: Node[] = [];
  public edges: Edge[] = [];

  /** Statement payloads keyed by node id. */
  public statements: Map<number, Statement> = new Map();
  /** Procedures keyed by procedure id. */
  public procedures: Map<number, Procedure> = new Map();
  /** Map from procedure name → procedure id (for call resolution). */
  public procByName: Map<string, number> = new Map();
  /** Call sites that target each callee proc (for exit → return propagation). */
  public callersOf: Map<number, number[]> = new Map();

  private outAdj: Map<number, Map<EdgeKindTag, number[]>> = new Map();
  private inAdj: Map<number, Map<EdgeKindTag, number[]>> = new Map();

  private filePaths: string[] = [];
  private fileMap: Map<string, number> = new Map();

  public internFile(path: string): number {
    if (this.fileMap.has(path)) { return this.fileMap.get(path)!; }
    const id = this.filePaths.length;
    this.filePaths.push(path);
    this.fileMap.set(path, id);
    return id;
  }

  public filePath(fileId: number): string {
    return this.filePaths[fileId] ?? '';
  }

  public addNode(kind: NodeKind, fileId: number, range: [number, number], line?: number): number {
    const id = this.nodes.length;
    this.nodes.push({ id, kind, fileId, range, line });
    return id;
  }

  public setProcedure(nodeId: number, procId: number): void {
    const n = this.nodes[nodeId];
    if (n) { n.procedure = procId; }
  }

  public addEdge(src: number, dst: number, tag: EdgeKindTag, metadata?: any): void {
    const edgeId = this.edges.length;
    this.edges.push({ src, dst, tag, metadata });
    this.addToAdj(this.outAdj, src, tag, edgeId);
    this.addToAdj(this.inAdj, dst, tag, edgeId);
  }

  private addToAdj(map: Map<number, Map<EdgeKindTag, number[]>>, node: number, tag: EdgeKindTag, edgeId: number) {
    if (!map.has(node)) { map.set(node, new Map()); }
    const inner = map.get(node)!;
    if (!inner.has(tag)) { inner.set(tag, []); }
    inner.get(tag)!.push(edgeId);
  }

  public outEdges(src: number, tag: EdgeKindTag): Edge[] {
    const indices = this.outAdj.get(src)?.get(tag) || [];
    return indices.map(idx => this.edges[idx]);
  }

  public inEdges(dst: number, tag: EdgeKindTag): Edge[] {
    const indices = this.inAdj.get(dst)?.get(tag) || [];
    return indices.map(idx => this.edges[idx]);
  }

  public addProcedure(p: Procedure): void {
    this.procedures.set(p.id, p);
    this.procByName.set(p.name, p.id);
    this.setProcedure(p.entry, p.id);
    this.setProcedure(p.exit, p.id);
  }

  public recordCaller(calleeProc: number, callSiteNode: number): void {
    const list = this.callersOf.get(calleeProc) ?? [];
    list.push(callSiteNode);
    this.callersOf.set(calleeProc, list);
  }
}
