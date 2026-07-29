import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const siteRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const outputRoot = join(siteRoot, ".tmp", "cloud-run-projection");
const wranglerRoot = join(siteRoot, ".tmp", "cloud-run-worker");

rmSync(outputRoot, { recursive: true, force: true });
rmSync(wranglerRoot, { recursive: true, force: true });
mkdirSync(outputRoot, { recursive: true });

execFileSync(process.execPath, [join(siteRoot, "scripts", "build-worker.mjs")], { cwd: siteRoot, stdio: "inherit" });
execFileSync(join(siteRoot, "node_modules", ".bin", "wrangler"), [
  "deploy", "--dry-run", "--outdir", wranglerRoot,
], { cwd: siteRoot, stdio: "inherit" });

writeFileSync(join(outputRoot, "worker.mjs"), readFileSync(join(wranglerRoot, "worker.js")));
writeFileSync(join(outputRoot, "package.json"), `${JSON.stringify({
  name: "561-group-gui-cloud-run-projection",
  private: true,
  type: "module",
  scripts: { start: "node server.mjs" },
}, null, 2)}\n`);
writeFileSync(join(outputRoot, "server.mjs"), `import { createServer } from "node:http";
import worker from "./worker.mjs";

const port = Number.parseInt(process.env.PORT ?? "8080", 10);
const operatorEmail = process.env.IAP_OPERATOR_EMAIL ?? "";
const chainReaderOrigin = new URL(process.env.MUD_CHAIN_READER_ORIGIN ?? "http://10.128.0.2:8562");
if (chainReaderOrigin.protocol !== "http:" || chainReaderOrigin.hostname !== "10.128.0.2" || chainReaderOrigin.port !== "8562") {
  throw new Error("MUD_CHAIN_READER_ORIGIN must name the fixed private history reader");
}
const environment = Object.freeze({
  IAP_OPERATOR_EMAIL: operatorEmail,
  MUD_CHAIN_READER: Object.freeze({
    async fetch(input, init) {
      const response = await fetch(new URL(new URL(input).pathname, chainReaderOrigin), init);
      if (!response.ok) console.error("chain reader refusal", response.status, await response.clone().text());
      return response;
    },
  }),
});

const warmup = await worker.fetch(new Request("https://gui.561.group/api/mud", {
  headers: { "x-goog-authenticated-user-email": "accounts.google.com:" + operatorEmail },
}), environment);
if (!warmup.ok) throw new Error("private dimension warmup refused: HTTP " + warmup.status + " " + await warmup.text());

createServer(async (incoming, outgoing) => {
  try {
    const body = incoming.method === "GET" || incoming.method === "HEAD" ? undefined : incoming;
    const request = new Request(new URL(incoming.url ?? "/", "https://gui.561.group"), {
      method: incoming.method,
      headers: incoming.headers,
      body,
      ...(body === undefined ? {} : { duplex: "half" }),
    });
    const response = await worker.fetch(request, environment);
    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    console.error(error);
    outgoing.writeHead(500, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
    outgoing.end("Internal Server Error\\n");
  }
}).listen(port, "0.0.0.0", () => console.log("561 Group GUI listening on 0.0.0.0:" + port));
`);

process.stdout.write(`${JSON.stringify({ type: "561GroupCloudRunProjection", outputRoot })}\n`);
