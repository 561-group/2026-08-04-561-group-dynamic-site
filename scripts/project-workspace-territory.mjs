#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { createCarrierAdmissionReceipt } from "@red-cup-engineering/modeled-union-dimension";
import { formatRml, parseRml, semanticId as rmnSemanticId } from "@red-cup-engineering/rmn-semantic-conformance";
import { catalogNodeWorkspaceSources, semanticId } from "@red-cup-engineering/typed-resource-catalog";

const siteRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(process.argv[2] ?? findWorkspaceRoot(siteRoot));
let stdin = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) stdin += chunk;
if (Buffer.byteLength(stdin, "utf8") > 4_194_304) throw new TypeError("pnpm workspace admission exceeds 4194304 UTF-8 bytes");
const admitted = JSON.parse(stdin);
if (!Array.isArray(admitted) || admitted.length === 0) throw new TypeError("expected pnpm --recursive list --depth -1 --json admission on stdin");

const packageAdmissions = admitted.filter(({ name }) => typeof name === "string" && name.length > 0);
const resources = await Promise.all(packageAdmissions.map(async ({ path }, index) => {
  const directory = resolve(String(path ?? ""));
  const proofPath = relative(workspaceRoot, directory);
  if (proofPath === ".." || proofPath.startsWith(`..${sep}`) || resolve(workspaceRoot, proofPath) !== directory) {
    throw new TypeError(`workspace admission[${index}] escapes the workspace root`);
  }
  return { path: proofPath ? `${proofPath.split(sep).join("/")}/package.json` : "package.json", content: await readFile(join(directory, "package.json"), "utf8") };
}));
const catalogReceipt = catalogNodeWorkspaceSources({ resources });
const workspaceDefinition = await readFile(join(workspaceRoot, "pnpm-workspace.yaml"), "utf8");
const missionSource = await readFile(join(workspaceRoot, "SEMIOTIC_FOAM_ONE_MACHINE.rml"), "utf8");
const missionTerm = parseRml(missionSource);
if (formatRml(missionTerm).trim() !== missionSource.trim()) throw new Error("SEMIOTIC_FOAM_ONE_MACHINE.rml is not canonical RMN v2");
const missionLaw = Object.freeze({
  type: "ModeledUnionMissionLawLocus",
  locus: "law:semiotic-foam-one-machine",
  carrierNi: rmnSemanticId(missionTerm),
  language: "rmn/v2",
});
const observationBody = {
  type: "NodeWorkspaceTerritoryObservationReceipt",
  version: 1,
  workspaceDefinitionNi: semanticId({ content: workspaceDefinition }),
  catalogReceiptNi: catalogReceipt.id,
  packageManifestNis: catalogReceipt.packages.map(({ manifestEvidence }) => manifestEvidence).sort(),
  denominator: catalogReceipt.denominator,
  missionLaw,
};
const observationReceipt = { ...observationBody, id: semanticId(observationBody) };
const carrierAdmissionReceipt = createCarrierAdmissionReceipt({
  carrier: { type: catalogReceipt.type, value: catalogReceipt },
  protocolVerificationReceiptNis: [observationReceipt.id],
});
const artifactBody = { type: "ModeledUnionWorkspaceTerritoryArtifact", version: 1, observationReceipt, carrierAdmissionReceipt };
const artifact = { ...artifactBody, id: semanticId(artifactBody) };
const outputDirectory = join(siteRoot, ".tmp", "mud-territory");
const artifactName = `${artifact.id.slice("ni:///sha-256;".length)}.json`;
await mkdir(outputDirectory, { recursive: true });
await writeFile(join(outputDirectory, artifactName), `${JSON.stringify(artifact)}\n`, { flag: "w" });
await writeFile(join(outputDirectory, "index.json"), `${JSON.stringify({ type: "ModeledUnionWorkspaceTerritoryArtifactIndex", version: 1, artifact: artifact.id, file: artifactName })}\n`, { flag: "w" });
process.stdout.write(`${JSON.stringify({ type: "ModeledUnionWorkspaceTerritoryProjection", artifact: artifact.id, carrier: carrierAdmissionReceipt.contentNi, packages: catalogReceipt.packages.length, relations: catalogReceipt.relations.length, output: relative(workspaceRoot, join(outputDirectory, artifactName)).split(sep).join("/") })}\n`);

function findWorkspaceRoot(start) {
  let at = resolve(start);
  for (;;) {
    if (existsSync(join(at, "pnpm-workspace.yaml"))) return at;
    const parent = dirname(at);
    if (parent === at) throw new Error("pnpm-workspace.yaml was not found above the site");
    at = parent;
  }
}
