import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { verifyEphemerisOffer } from "../scripts/verify-ephemeris-offer.mjs";
import generatedWorker from "../src/worker.mjs";

const worker = { fetch(request) { return generatedWorker.fetch(request, {}); } };

const base = { x402Version: 2, resource: {}, accepts: [{ scheme: "exact", network: "eip155:8453", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", payTo: "0x42F72C0a340A4A55C082Fe42483e87691D2bff64" }] };
function fixture({ moment = {}, precision = {} } = {}) {
  return async (url) => {
    const patch = url.includes("precision-moment") ? precision : moment;
    const amount = url.includes("precision-moment") ? "320000" : "40000";
    return new Response("{}", { status: 402, headers: { "payment-required": Buffer.from(JSON.stringify({ ...base, ...patch, resource: { url }, accepts: [{ ...base.accepts[0], amount, ...(patch.accepts?.[0] ?? {}) }] })).toString("base64url") } });
  };
}

test("qualifies the two public Base-USDC Ephemeris offers without paying", async () => {
  const result = await verifyEphemerisOffer({ fetchImpl: fixture() });
  assert.equal(result.qualified, true);
  assert.equal(result.offers.length, 2);
  assert.equal(result.authority.paymentAttempted, false);
});

test("refuses a market card when the payee or price drifts", async () => {
  const result = await verifyEphemerisOffer({ fetchImpl: fixture({ moment: { accepts: [{ payTo: "0x1111111111111111111111111111111111111111", amount: "9" }] } }) });
  assert.equal(result.qualified, false);
  assert.deepEqual(result.offers[0].problems, ["payee drift", "price drift"]);
});

test("one generated carrier serves the 561 Group apex and market projection", async () => {
  const apex = await worker.fetch(new Request("https://561.group/"));
  const apexBody = await apex.text();
  assert.equal(apex.status, 200);
  assert.match(apexBody, /Black Liberation/);
  assert.match(apexBody, /#F2EAD8/);
  assert.match(apexBody, /github\.com\/561-group/);

  const market = await worker.fetch(new Request("https://market.561.group/"));
  const marketBody = await market.text();
  assert.equal(market.status, 200);
  assert.match(marketBody, /Paid Ephemeris Gateway/);
  assert.match(marketBody, /eip155:8453/);
  assert.match(marketBody, /0x42F72C0a340A4A55C082Fe42483e87691D2bff64/);
});

test("the stale apex market path redirects to the market hostname", async () => {
  const response = await worker.fetch(new Request("https://561.group/market"));
  assert.equal(response.status, 308);
  assert.equal(response.headers.get("location"), "https://market.561.group/");
});

test("the public projection contains neither local citations nor an unserved webmention capability", async () => {
  const [apex, home, manifest, workerSource] = await Promise.all([
    worker.fetch(new Request("https://561.group/")),
    worker.fetch(new Request("https://561.group/home")),
    worker.fetch(new Request("https://561.group/site.json")),
    readFile(new URL("../src/worker.mjs", import.meta.url), "utf8"),
  ]);
  const [apexBody, homeBody, manifestBody] = await Promise.all([apex.text(), home.text(), manifest.text()]);
  assert.equal(apex.status, 200);
  assert.equal(home.status, 200);
  assert.equal(manifest.status, 200);
  assert.doesNotMatch(apexBody, /\/home\//u);
  assert.doesNotMatch(manifestBody, /\/home\//u);
  assert.match(homeBody, /github\.com\/561-group\/561-group-site\/blob\/main\/content\/home\.md/u);
  assert.doesNotMatch(apexBody, /rel=\\"webmention\\"/u);
  assert.doesNotMatch(manifestBody, /webmention/u);
  assert.doesNotMatch(workerSource, /2026-07-22T22:56:15\.000Z/u);
});

async function accessAdmission() {
  const teamDomain = "union.cloudflareaccess.com";
  const audience = "gui-audience";
  const email = "operator@example.com";
  const pair = await webcrypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const publicJwk = { ...await webcrypto.subtle.exportKey("jwk", pair.publicKey), kid: "access-key", alg: "RS256", use: "sig" };
  const base64url = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");
  const protectedSegment = base64url({ alg: "RS256", kid: publicJwk.kid });
  const payloadSegment = base64url({ email, iss: `https://${teamDomain}`, aud: audience, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 300 });
  const signingInput = `${protectedSegment}.${payloadSegment}`;
  const signature = await webcrypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(signingInput));
  const token = `${signingInput}.${Buffer.from(signature).toString("base64url")}`;
  return {
    environment: { ACCESS_TEAM_DOMAIN: teamDomain, ACCESS_POLICY_AUD: audience, ACCESS_OPERATOR_EMAIL: email },
    request(url, init = {}) { return new Request(url, { ...init, headers: { ...init.headers, "cf-access-jwt-assertion": token } }); },
    jwks: { keys: [publicJwk] },
  };
}

test("gui.561.group is an Access-admitted projection of only the cloud-chain witness", async () => {
  const access = await accessAdmission();
  const environment = {
    ...access.environment,
    MUD_CHAIN_READER: { fetch: async (_url, init) => {
      const call = JSON.parse(init.body);
      return Response.json({ jsonrpc: "2.0", id: 1, result: call.method === "eth_blockNumber" ? "0x15f3" : [] });
    } },
  };

  assert.equal((await generatedWorker.fetch(new Request("https://gui.561.group/"), environment)).status, 403);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => String(input) === `https://${access.environment.ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`
    ? Response.json(access.jwks)
    : originalFetch(input, init);
  try {
    const gui = await generatedWorker.fetch(access.request("https://gui.561.group/"), environment);
    assert.equal(gui.status, 200);
    assert.match(await gui.text(), /Semiotic Foam/u);

    const read = await generatedWorker.fetch(access.request("https://gui.561.group/api/mud"), environment);
    assert.equal(read.status, 200);
    assert.equal(read.headers.get("access-control-allow-origin"), null);
    const state = await read.json();
    assert.deepEqual(state.presentation.ledger, { chainId: "eip155:5615611", exchange: "0xc4234dc42c9d93bc7d61b0354aba2729ae52e322" });
    assert.deepEqual(state.presentation.events, []);

    const play = await generatedWorker.fetch(access.request("https://gui.561.group/api/mud/play", { method: "POST" }), environment);
    assert.equal(play.status, 503);
    assert.equal((await play.json()).type, "SemioticExchangeActuatorUnavailable");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the MUD API capability is not exposed on the apex hostname", async () => {
  const response = await worker.fetch(new Request("https://561.group/api/mud"));
  assert.equal(response.status, 404);
});
