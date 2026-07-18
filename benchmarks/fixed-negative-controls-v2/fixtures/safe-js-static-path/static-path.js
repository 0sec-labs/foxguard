import path from "node:path";

const assetRoot = path.join(import.meta.dirname, "public");

export function assetPath(name) {
  const allowed = new Set(["logo.svg", "main.css"]);
  if (!allowed.has(name)) throw new Error("unknown asset");
  return path.join(assetRoot, name);
}
