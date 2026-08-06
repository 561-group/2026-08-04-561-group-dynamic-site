#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { createCarrierAdmissionReceipt } from "@red-cup-engineering/modeled-union-dimension";
import { catalogNodeWorkspaceSources, semanticId } from "@red-cup-engineering/typed-resource-catalog";
import { observeWorkspaceApiSurface } from "../src/jsnode-knowledge.mjs";

const siteRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(process.argv[2] ?? findWorkspaceRoot(siteRoot));
let stdin = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) stdin += chunk;
if (Buffer.byteLength(stdin, "utf8") > 4_194_304) throw new TypeError("pnpm workspace admission exceeds 4194304 UTF-8 bytes");
const admitted = JSON.parse(stdin);
if (!Array.isArray(admitted) || admitted.length === 0) throw new TypeError("expected pnpm --recursive list --depth -1 --json admission on stdin");

const listedAdmissions = admitted.filter(({ name }) => typeof name === "string" && name.length > 0);
const networkAdmissions = await discoverNetworkPackageAdmissions(workspaceRoot);
const packageAdmissions = networkAdmissions.length > listedAdmissions.length ? networkAdmissions : listedAdmissions;
const resources = await Promise.all(packageAdmissions.map(async ({ path }, index) => {
  const directory = resolve(String(path ?? ""));
  const proofPath = relative(workspaceRoot, directory);
  if (proofPath === ".." || proofPath.startsWith(`..${sep}`) || resolve(workspaceRoot, proofPath) !== directory) {
    throw new TypeError(`workspace admission[${index}] escapes the workspace root`);
  }
  return { path: proofPath ? `${proofPath.split(sep).join("/")}/package.json` : "package.json", content: await readFile(join(directory, "package.json"), "utf8") };
}));
const catalogReceipt = catalogNodeWorkspaceSources({ resources });
const apiSurfaceReceipt = await observeWorkspaceApiSurface(workspaceRoot, packageAdmissions);
const workspaceDefinition = await readFile(join(workspaceRoot, "pnpm-workspace.yaml"), "utf8");
const observationBody = {
  type: "NodeWorkspaceTerritoryObservationReceipt",
  version: 1,
  workspaceDefinitionNi: semanticId({ content: workspaceDefinition }),
  catalogReceiptNi: catalogReceipt.id,
  apiSurfaceReceiptNi: apiSurfaceReceipt.id,
  packageManifestNis: catalogReceipt.packages.map(({ manifestEvidence }) => manifestEvidence).sort(),
  denominator: catalogReceipt.denominator,
};
const observationReceipt = { ...observationBody, id: semanticId(observationBody) };
const carrierAdmissionReceipt = createCarrierAdmissionReceipt({
  carrier: { type: catalogReceipt.type, value: catalogReceipt },
  protocolVerificationReceiptNis: [observationReceipt.id],
});
const artifactBody = { type: "ModeledUnionWorkspaceTerritoryArtifact", version: 1, observationReceipt, carrierAdmissionReceipt, apiSurfaceReceipt };
const artifact = { ...artifactBody, id: semanticId(artifactBody) };
const outputDirectory = join(siteRoot, ".tmp", "mud-territory");
const artifactName = `${artifact.id.slice("ni:///sha-256;".length)}.json`;
await mkdir(outputDirectory, { recursive: true });
await writeFile(join(outputDirectory, artifactName), `${JSON.stringify(artifact)}\n`, { flag: "w" });
await writeFile(join(outputDirectory, "index.json"), `${JSON.stringify({ type: "ModeledUnionWorkspaceTerritoryArtifactIndex", version: 1, artifact: artifact.id, file: artifactName })}\n`, { flag: "w" });
process.stdout.write(`${JSON.stringify({ type: "ModeledUnionWorkspaceTerritoryProjection", artifact: artifact.id, carrier: carrierAdmissionReceipt.contentNi, packages: catalogReceipt.packages.length, symbols: apiSurfaceReceipt.symbols.length, relations: catalogReceipt.relations.length, output: relative(workspaceRoot, join(outputDirectory, artifactName)).split(sep).join("/") })}\n`);

function findWorkspaceRoot(start) {
  let at = resolve(start);
  for (;;) {
    if (existsSync(join(at, "pnpm-workspace.yaml"))) return at;
    const parent = dirname(at);
    if (parent === at) throw new Error("pnpm-workspace.yaml was not found above the site");
    at = parent;
  }
}

async function discoverNetworkPackageAdmissions(root) {
  const base = join(root, "lib", "emsenn", "services", "561-group");
  const packages = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const proofPath = `/${relative(base, path).split(sep).join("/")}${entry.isDirectory() ? "/" : ""}`;
      if (entry.isDirectory()) {
        if ([".git", ".tmp", ".venv", "dist", "node_modules"].includes(entry.name)
            || proofPath.includes("/.claude/worktrees/") || proofPath.includes("/content/assets/legacy/")
            || proofPath.includes("/content/retired-carriers/") || proofPath.includes("/data/runtime-images/")
            || proofPath.includes("/lib/legacy/") || proofPath.includes("/lib/material/")) continue;
        await walk(path);
      } else if (entry.name === "package.json") {
        let manifest;
        try { manifest = JSON.parse(await readFile(path, "utf8")); } catch { continue; }
        if (typeof manifest.name === "string" && manifest.name !== "" && typeof manifest.version === "string" && manifest.version !== "") {
          packages.push({ name: manifest.name, version: manifest.version, path: directory });
        }
      }
    }
  }
  await walk(base);
  const byName = new Map();
  for (const admission of packages.sort((left, right) => left.name.localeCompare(right.name) || left.path.localeCompare(right.path))) {
    if (byName.has(admission.name)) throw new TypeError(`network package identity ${admission.name} has more than one live source`);
    byName.set(admission.name, admission);
  }
  return [...byName.values()];
}
