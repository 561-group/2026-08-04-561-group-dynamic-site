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
writeFileSync(join(outputRoot, "Dockerfile"), `FROM node:22-slim
WORKDIR /app
COPY package.json worker.mjs server.mjs ./
ENV NODE_ENV=production PORT=8080
CMD ["node", "server.mjs"]
`);
writeFileSync(join(outputRoot, "cloudbuild.yaml"), `steps:
  - name: gcr.io/cloud-builders/docker
    args: ["build", "--pull", "--tag", "${"${_IMAGE}"}", "."]
images: ["${"${_IMAGE}"}"]
`);
writeFileSync(join(outputRoot, "server.mjs"), `import { createServer } from "node:http";
import worker from "./worker.mjs";

const port = Number.parseInt(process.env.PORT ?? "8080", 10);
const operatorEmail = process.env.IAP_OPERATOR_EMAIL ?? "";
const publicProjection = process.env.MUD_PUBLIC_PROJECTION ?? "";
const chainReaderOrigin = new URL(process.env.MUD_CHAIN_READER_ORIGIN ?? "http://10.128.0.2:8563");
const mudDemandActorOrigin = new URL(process.env.MUD_DEMAND_ACTOR_ORIGIN ?? "http://mud-demand-actor.internal");
if (chainReaderOrigin.protocol !== "http:" || chainReaderOrigin.hostname !== "10.128.0.2" || chainReaderOrigin.port !== "8563") {
  throw new Error("MUD_CHAIN_READER_ORIGIN must name the fixed private history reader");
}
if (mudDemandActorOrigin.protocol !== "http:" || !mudDemandActorOrigin.hostname.endsWith(".internal")) {
  throw new Error("MUD_DEMAND_ACTOR_ORIGIN must name the private MUD ActivityPub actor");
}
const environment = Object.freeze({
  IAP_OPERATOR_EMAIL: operatorEmail,
  MUD_PUBLIC_PROJECTION: publicProjection,
  MUD_CHAIN_READER: Object.freeze({
    async fetch(input, init) {
      const response = await fetch(new URL("/", chainReaderOrigin), init);
      if (!response.ok) console.error("chain reader refusal", response.status, await response.clone().text());
      return response;
    },
  }),
  MUD_DEMAND_ACTOR: Object.freeze({
    async fetch(_input, init) {
      const response = await fetch(new URL("/v1/mud/demands", mudDemandActorOrigin), init);
      if (!response.ok) console.error("MUD demand actor refusal", response.status, await response.clone().text());
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
