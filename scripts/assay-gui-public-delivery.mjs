#!/usr/bin/env node
import { promises as dns } from "node:dns";
import tls from "node:tls";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const formationPath = join(root, "content", "deployments", "gui-public-delivery-formation.json");
const residue = (check, status, code, detail) => ({ check, status, code, detail });

export async function readGuiPublicDeliveryFormation(read = readFile) {
  return JSON.parse(await read(formationPath, "utf8"));
}

export function observeTls(hostname, connect = tls.connect) {
  return new Promise((resolve) => {
    const socket = connect({ host: hostname, port: 443, servername: hostname, rejectUnauthorized: true });
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      socket.end();
      resolve(residue("tls", "pass", "TLS_VALID", { subject: certificate.subject?.CN ?? null }));
    });
    socket.once("error", (error) => resolve(residue("tls", "fail", "TLS_UNAVAILABLE", { message: error.message })));
  });
}

export async function assayGuiPublicDelivery(options = {}) {
  const formation = options.formation ?? await readGuiPublicDeliveryFormation(options.read);
  const target = formation.independentAssayVector.target;
  const resolver = options.resolve4 ?? dns.resolve4;
  const fetcher = options.fetch ?? globalThis.fetch;
  const results = [];
  try {
    const addresses = await resolver(target.hostname);
    results.push(residue("dns", addresses.length ? "pass" : "fail", addresses.length ? "DNS_RESOLVED" : "DNS_EMPTY", { addresses }));
  } catch (error) {
    results.push(residue("dns", "fail", "DNS_UNRESOLVED", { message: error.message }));
  }
  results.push(await (options.observeTls ?? observeTls)(target.hostname, options.connect));
  let response;
  try {
    response = await fetcher(`https://${target.hostname}${target.path}`, { redirect: "manual", headers: { "user-agent": "561-group-independent-assay/1" } });
    const status = response.status >= 200 && response.status < 400 ? "pass" : "fail";
    results.push(residue("http", status, status === "pass" ? "HTTP_REACHABLE" : "HTTP_UNEXPECTED_STATUS", { statusCode: response.status }));
    results.push(residue("path", status, status === "pass" ? "PATH_REACHABLE" : "PATH_UNEXPECTED_STATUS", { path: target.path, statusCode: response.status }));
  } catch (error) {
    results.push(residue("http", "fail", "HTTP_UNREACHABLE", { message: error.message }));
    results.push(residue("path", "fail", "PATH_UNOBSERVED", { path: target.path }));
  }
  results.push(residue("access-policy", "not-claimed", "ADMISSION_UNSETTLED", { reason: formation.admission.refusal }));
  results.push(residue("provider-effect", "not-applicable", "EXTERNAL_ASSAY_ONLY", { reason: "Provider deployment state is outside this independent observer." }));
  return {
    type: "GuiPublicDeliveryIndependentAssay",
    target,
    residues: results,
    summary: Object.fromEntries(["pass", "fail", "not-claimed", "not-applicable"].map((status) => [status, results.filter((item) => item.status === status).length]))
  };
}

const direct = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (direct) {
  const result = await assayGuiPublicDelivery();
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (result.summary.fail) process.exitCode = 1;
}
