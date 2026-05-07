String normalizePath(String path) => path.replaceAll('\\', '/');

String basename(String path) {
  final normalized = normalizePath(path);
  final slashIndex = normalized.lastIndexOf('/');
  return slashIndex == -1 ? normalized : normalized.substring(slashIndex + 1);
}

String dirname(String path) {
  final normalized = normalizePath(path);
  final slashIndex = normalized.lastIndexOf('/');
  if (slashIndex == -1) {
    return '.';
  }
  if (slashIndex == 0) {
    return '/';
  }
  return normalized.substring(0, slashIndex);
}

String joinPath(String directory, String name) {
  if (directory.isEmpty) return name;
  final normalized = normalizePath(directory);
  if (normalized.endsWith('/')) {
    return '$normalized$name';
  }
  return '$normalized/$name';
}

String relativePath(String rootPath, String fullPath) {
  final normalizedRoot = normalizePath(
    rootPath,
  ).replaceFirst(RegExp(r'/$'), '');
  final normalizedFull = normalizePath(fullPath);
  if (normalizedFull == normalizedRoot) {
    return '.';
  }

  final prefix = '$normalizedRoot/';
  if (normalizedFull.startsWith(prefix)) {
    return normalizedFull.substring(prefix.length);
  }

  return normalizedFull;
}
