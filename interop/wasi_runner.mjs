import fs from "node:fs";
import { WASI } from "node:wasi";

const wasmPath = process.argv[2];
if (!wasmPath) {
  throw new Error("usage: node wasi_runner.mjs adapter.wasm");
}
const wasi = new WASI({ version: "preview1", args: [], env: {}, preopens: {} });
const module = await WebAssembly.compile(fs.readFileSync(wasmPath));
const instance = await WebAssembly.instantiate(module, wasi.getImportObject());
wasi.start(instance);
