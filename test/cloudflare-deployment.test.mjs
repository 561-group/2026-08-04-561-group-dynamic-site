import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  executeCloudflareDeployment,
  preflightCloudflareDeployment,
  readCloudflareDeploymentRequest
} from "../scripts/cloudflare-deployment.mjs";
import { LinuxCloudflareAuthenticationRefusal } from "@red-cup-engineering/linux-cloudflare-authentication-cell";

test("site authentication request binds the one named profile and account", async () => {
  const request = await readCloudflareDeploymentRequest();
  assert.equal(request.profile, "bare-cedar-fog-semantic-content-identity");
  assert.equal(request.expectedAccountId, "337e54ee6dc7d488933f473204a6d89e");
  assert.equal(request.browser, true);
  assert.equal(request.callbackHost, "127.0.0.1");
  assert.equal(request.callbackPort, 8976);
  assert.deepEqual(request.scopes, [
    "account:read",
    "connectivity:admin",
    "user:read",
    "workers_routes:write",
    "workers_scripts:write",
    "zone:read"
  ]);
  assert.match(request.settlementDirectory, /sites\/561\.group$/u);
});

test("preflight returns an actionable typed refusal for an expired grant", async () => {
  const result = await preflightCloudflareDeployment({
    inspect: async () => {
      throw new LinuxCloudflareAuthenticationRefusal("AUTHORIZATION_EXPIRED", "named profile exists but is not logged in", { profile: "bare-cedar-fog-semantic-content-identity" });
    }
  });
  assert.equal(result.type, "CloudflareDeploymentRefusal");
  assert.equal(result.code, "AUTHORIZATION_EXPIRED");
  assert.equal(result.recovery, "node_modules/.bin/authenticate-linux-colony-with-cloudflare ops/cloudflare-authentication-request.json");
  assert.equal(result.credentialReturned, false);
});

test("dry-run uses only the site-owned build and Wrangler after verified inspection", async () => {
  const calls = [];
  const result = await executeCloudflareDeployment("dry-run", {
    inspect: async (request) => ({
      profile: request.profile,
      account: { id: request.expectedAccountId },
      credentialCustody: "linux-secret-service",
      secretToolProbe: "compatible"
    }),
    execute: async (command, args, options) => {
      calls.push({ command, args, options });
      return { status: 0 };
    }
  });
  assert.equal(result.deployed, false);
  assert.equal(calls.length, 2);
  assert.match(calls[0].args[0], /scripts\/build-worker\.mjs$/u);
  assert.match(calls[1].command, /sites\/561\.group\/node_modules\/\.bin\/wrangler$/u);
  assert.deepEqual(calls[1].args, ["deploy", "--profile", "bare-cedar-fog-semantic-content-identity", "--dry-run"]);
  assert.match(calls[1].options.env.WRANGLER_LOG_PATH, /561-group-cloudflare-deployment-wrangler\.log$/u);
});

test("cloud history tunnel is a token-file-only QUIC user service", async () => {
  const unit = await readFile(new URL("../ops/systemd/union-semiotic-exchange-workers-vpc-tunnel.service", import.meta.url), "utf8");
  assert.match(unit, /Requires=union-semiotic-exchange-history-reader\.service/u);
  assert.match(unit, /--protocol quic run --token-file %h\/\.config\/cloudflared\/semiotic-exchange-history-workers-vpc\.token/u);
  assert.doesNotMatch(unit, /--token(?:\s|=)|credentials-file|cert\.pem/u);
});
