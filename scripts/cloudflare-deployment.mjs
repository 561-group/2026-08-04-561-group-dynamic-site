#!/usr/bin/env node
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import {
  inspectLinuxCloudflareAuthentication,
  LinuxCloudflareAuthenticationRefusal
} from "@red-cup-engineering/linux-cloudflare-authentication-service";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const siteRoot = join(scriptDirectory, "..");
const requestPath = join(siteRoot, "ops", "cloudflare-authentication-request.json");
const wranglerPath = join(siteRoot, "node_modules", ".bin", "wrangler");
const secretToolPath = fileURLToPath(import.meta.resolve("@red-cup-engineering/linux-cloudflare-authentication-service/libexec/secret-tool"));
const compatibilityDirectory = dirname(secretToolPath);
const reauthorizeCommand = "node_modules/.bin/authenticate-linux-colony-with-cloudflare ops/cloudflare-authentication-request.json";

const secretEnvironmentKeys = new Set([
  "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL",
  "CF_API_TOKEN", "CF_API_KEY", "CF_EMAIL"
]);

function deploymentEnvironment(environment = process.env) {
  const safe = Object.fromEntries(Object.entries(environment).filter(([key]) => !secretEnvironmentKeys.has(key)));
  safe.CLOUDFLARE_AUTH_USE_KEYRING = "true";
  safe.WRANGLER_LOG_PATH ??= join(tmpdir(), "561-group-cloudflare-deployment-wrangler.log");
  safe.PATH = `${compatibilityDirectory}:${environment.PATH ?? "/usr/local/bin:/usr/bin:/bin"}`;
  return safe;
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    child.on("error", reject);
    child.on("close", (status, signal) => {
      if (status !== 0) {
        reject(new Error(`${command} ${args[0] ?? ""} failed (${signal ?? status})`));
        return;
      }
      resolve({ status: 0 });
    });
  });
}

export async function readCloudflareDeploymentRequest() {
  const request = JSON.parse(await readFile(requestPath, "utf8"));
  return { ...request, settlementDirectory: siteRoot };
}

export async function preflightCloudflareDeployment(options = {}) {
  const major = Number.parseInt(process.versions.node.split(".")[0], 10);
  if (major < 22) {
    return {
      type: "CloudflareDeploymentRefusal",
      code: "NODE_RUNTIME_TOO_OLD",
      message: `Cloudflare projection requires Node >=22; found ${process.versions.node}`,
      recovery: "activate a Node >=22 runtime",
      deployable: false
    };
  }
  const request = await readCloudflareDeploymentRequest();
  try {
    const inspection = await (options.inspect ?? inspectLinuxCloudflareAuthentication)(request, {
      wranglerPath,
      compatibilityDirectory,
      environment: options.environment ?? process.env
    });
    return {
      type: "CloudflareDeploymentPreflight",
      profile: inspection.profile,
      account: inspection.account,
      credentialCustody: inspection.credentialCustody,
      secretToolProbe: inspection.secretToolProbe,
      credentialReturned: false,
      deployable: true
    };
  } catch (error) {
    const refusal = error instanceof LinuxCloudflareAuthenticationRefusal
      ? error.toJSON()
      : { type: "LinuxCloudflareAuthenticationRefusal", code: "PREFLIGHT_FAILED", message: error instanceof Error ? error.message : String(error) };
    return {
      type: "CloudflareDeploymentRefusal",
      code: refusal.code,
      message: refusal.message,
      evidence: refusal.evidence ?? {},
      recovery: reauthorizeCommand,
      credentialReturned: false,
      deployable: false
    };
  }
}

export async function executeCloudflareDeployment(mode, options = {}) {
  if (!new Set(["preflight", "dry-run", "deploy"]).has(mode)) {
    throw new TypeError("mode must be preflight, dry-run, or deploy");
  }
  const preflight = await preflightCloudflareDeployment(options);
  if (!preflight.deployable || mode === "preflight") return preflight;

  const execute = options.execute ?? run;
  const environment = deploymentEnvironment(options.environment ?? process.env);
  await execute(process.execPath, [join(siteRoot, "scripts", "build-worker.mjs")], {
    cwd: siteRoot, env: environment, stdio: "inherit"
  });
  const request = await readCloudflareDeploymentRequest();
  const args = ["deploy", "--profile", request.profile];
  if (mode === "dry-run") args.push("--dry-run");
  await execute(wranglerPath, args, { cwd: siteRoot, env: environment, stdio: "inherit" });
  return {
    type: "CloudflareDeploymentReceipt",
    mode,
    profile: request.profile,
    account: { id: request.expectedAccountId },
    worker: "561-group-site",
    routes: ["561.group/*", "market.561.group", "gui.561.group"],
    credentialReturned: false,
    deployed: mode === "deploy"
  };
}

const invokedDirectly = process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  const mode = process.argv[2] ?? "preflight";
  try {
    const result = await executeCloudflareDeployment(mode);
    const stream = result.deployable === false ? process.stderr : process.stdout;
    stream.write(`${JSON.stringify(result)}\n`);
    if (result.deployable === false) process.exitCode = 78;
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      type: "CloudflareDeploymentRefusal",
      code: "DEPLOYMENT_FAILED",
      message: error instanceof Error ? error.message : String(error),
      credentialReturned: false,
      deployable: false
    })}\n`);
    process.exitCode = 1;
  }
}
