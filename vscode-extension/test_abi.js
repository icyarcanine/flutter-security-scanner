const Parser = require('web-tree-sitter');
const path = require('path');
(async () => {
  await Parser.init();
  const wasmPath = require.resolve('tree-sitter-wasms/out/tree-sitter-javascript.wasm');
  try {
    const lang = await Parser.Language.load(wasmPath);
    console.log("Success! ABI is compatible.");
  } catch (e) {
    console.error("Failed ABI:", e.message);
  }
})();
