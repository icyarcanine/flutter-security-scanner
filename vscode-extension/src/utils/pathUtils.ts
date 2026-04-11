export function normalizePath(p: string): string {
  return p.replace(/\\/g, '/');
}

export function basename(p: string): string {
  const normalized = normalizePath(p);
  const idx = normalized.lastIndexOf('/');
  return idx === -1 ? normalized : normalized.substring(idx + 1);
}

export function dirname(p: string): string {
  const normalized = normalizePath(p);
  const idx = normalized.lastIndexOf('/');
  if (idx === -1) { return '.'; }
  if (idx === 0) { return '/'; }
  return normalized.substring(0, idx);
}

export function relativePath(rootPath: string, fullPath: string): string {
  const normalizedRoot = normalizePath(rootPath).replace(/\/$/, '');
  const normalizedFull = normalizePath(fullPath);
  if (normalizedFull === normalizedRoot) { return '.'; }
  const prefix = `${normalizedRoot}/`;
  if (normalizedFull.startsWith(prefix)) {
    return normalizedFull.substring(prefix.length);
  }
  return normalizedFull;
}
