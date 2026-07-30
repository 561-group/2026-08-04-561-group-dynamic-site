import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createCarrierAdmissionReceipt } from "@red-cup-engineering/modeled-union-dimension";
import { admitMudOperator, createCloudMudServices, handleMudApi, MUD_CLIENT, MUD_LEDGER } from "../src/mud-face.mjs";

const controller = "0x08E4B3bc9ef76b403879C0eC372d1Fd146E3a07B";
const id = (byte) => `0x${byte.repeat(64)}`;
const ni = (label) => `ni:///sha-256;${createHash("sha256").update(label).digest("base64url")}`;
const chainPosition = (logIndex) => ({ blockNumber: 5619n, blockHash: id("a"), transactionHash: id("b"), logIndex });
const cell = id("1"), law = id("2"), demand = id("3"), offer = id("4");
const history = Object.freeze([
  { kind: "CellSeated", chainPosition: chainPosition(0), cell, controller, law, carrierNi: ni("cell") },
  { kind: "DemandRaised", chainPosition: chainPosition(1), demand, raiser: controller, wantedLaw: law, grounding: id("5"), carrierNi: ni("demand") },
  { kind: "DemandOffered", chainPosition: chainPosition(2), demand, offer, cell, controller, carrierNi: ni("offer") },
]);
const settledHistory = Object.freeze([
  ...history,
  { kind: "PurchaseMoved", chainPosition: chainPosition(3), demand, offer, cell, raiser: controller, controller },
  { kind: "DemandSettled", chainPosition: chainPosition(4), demand, cell, controller, result: id("6"), carrierNi: ni("result") },
]);
const territoryCarrier = createCarrierAdmissionReceipt({
  carrier: { type: "NodeWorkspaceSourceCatalogReceipt", value: { id: ni("test-workspace-catalog"), type: "NodeWorkspaceSourceCatalogReceipt", version: 1, denominator: { type: "admitted-package-manifest-set", count: 0 }, packages: [], relations: [] } },
  protocolVerificationReceiptNis: [ni("test-workspace-observation")],
});
const territoryArtifact = Object.freeze({ type: "ModeledUnionWorkspaceTerritoryArtifact", version: 1, carrierAdmissionReceipt: territoryCarrier });

function projectedWorkspaceTerritory() {
  const root = new URL("../.tmp/mud-territory/", import.meta.url);
  const index = JSON.parse(readFileSync(new URL("index.json", root), "utf8"));
  return JSON.parse(readFileSync(new URL(index.file, root), "utf8"));
}

test("the browser face projects its loci and arena from live SemioticExchange history", async () => {
  const response = await handleMudApi(new Request(`https://gui.561.group/api/mud?actor=${controller}`), "read", {
    readSemioticExchangeHistory: async () => history,
    readWorkspaceTerritory: async () => territoryArtifact,
  });
  assert.equal(response.status, 200, await response.clone().text());
  const state = await response.json();
  assert.deepEqual(state.presentation.events.map(({ kind }) => kind), ["CellSeated", "DemandRaised", "DemandOffered"]);
  assert.deepEqual(state.presentation.ledger, MUD_LEDGER);
  assert.equal(state.geometry.type, "GyrobifastigiumJ26");
  assert.equal(state.embodiment.type, "DiamondBeadJ26Embodiment");
  assert.deepEqual(state.embodiment.beadAdjacency.thread, state.embodiment.causalCarrier.sequencing);
  assert.deepEqual(state.embodiment.polarization.colors.map(({ color }) => color), [0, 1, 0]);
  assert.ok(state.restrictedArena.actions.some((action) => action.operation === "purchaseMove" && action.offer === offer));
  assert.ok(state.restrictedArena.actions.every((action) => action.available === false));
  assert.ok(state.cells.every(({ id: locus }) => !["bamboo-court", "jade-gate", "cloud-bridge"].includes(locus)));
});

test("the browser face absorbs legacy Teraum topology as a lawful local perception", async () => {
  const response = await handleMudApi(new Request(`https://gui.561.group/api/mud?actor=${controller}&world-locus=caliper-street`), "read", {
    readSemioticExchangeHistory: async () => settledHistory,
    readWorkspaceTerritory: async () => territoryArtifact,
  });
  assert.equal(response.status, 200);
  const state = await response.json();
  assert.equal(state.world.type, "TeraumLocalPerception");
  assert.equal(state.world.owner, "@561-group/site:/api/mud");
  assert.equal(state.world.position, "caliper-street");
  assert.deepEqual(state.world.exits, [{ direction: "114", target: "twisted-alembic", lawful: true }]);
  assert.equal(state.world.settlements.length, 1);
  assert.ok(state.world.obstructions.every(({ position }) => position === "caliper-street"));
});

test("a directional controller gesture becomes a canonical local lawful move, not browser world state", async () => {
  const response = await handleMudApi(new Request("https://gui.561.group/api/mud/conversation", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: "walk east", locus: cell, worldMove: { from: "central-plains", direction: "east" } }),
  }), "conversation", {
    readSemioticExchangeHistory: async () => history,
    readWorkspaceTerritory: async () => territoryArtifact,
  });
  assert.equal(response.status, 202, await response.clone().text());
  const value = await response.json();
  assert.deepEqual(value.worldMove, {
    type: "TeraumLawfulLocalMove", from: "central-plains", direction: "east", to: "farsteppes",
    durability: "observer-local until a separately enabled settlement move changes the witnessed world",
  });
  assert.equal(value.world.position, "farsteppes");
  assert.doesNotMatch(JSON.stringify(value), /chainAppend.*submitted/u);
});

test("the browser projection groups witnessed demand moves into causal threads and preserves frozen arena joints", async () => {
  const response = await handleMudApi(new Request(`https://gui.561.group/api/mud?actor=${controller}`), "read", {
    readSemioticExchangeHistory: async () => settledHistory,
    readWorkspaceTerritory: async () => territoryArtifact,
  });
  assert.equal(response.status, 200);
  const state = await response.json();
  const [thread] = state.causalFlow.threads;
  assert.equal(state.causalFlow.type, "SemioticExchangeCausalFlow");
  assert.equal(thread.demand, demand);
  assert.equal(thread.phase, "settled");
  assert.deepEqual(thread.events.map(({ kind }) => kind), ["DemandRaised", "DemandOffered", "PurchaseMoved", "DemandSettled"]);
  assert.equal(thread.raiser, controller);
  assert.equal(thread.controller, controller);
  assert.equal(thread.cell, cell);
  assert.ok(thread.causalRelations.length >= 3);
  assert.ok(thread.restrictedJoints.every(({ available }) => available === false));
  assert.ok(state.causalFlow.frozenJoints.every(({ available }) => available === false));
});

test("the projected private browser client is executable JavaScript", () => {
  assert.doesNotThrow(() => new Function(MUD_CLIENT));
  assert.match(MUD_CLIENT, /frozen /u);
});

test("the private MUD traverses every currently admitted workspace package through exact proof paths", async () => {
  const artifact = projectedWorkspaceTerritory();
  const admittedPackages = artifact.carrierAdmissionReceipt.carrier.value.packages;
  const response = await handleMudApi(new Request(`https://gui.561.group/api/mud?actor=${controller}`), "read", {
    readSemioticExchangeHistory: async () => history,
    readWorkspaceTerritory: async () => artifact,
  });
  assert.equal(response.status, 200);
  const state = await response.json();
  assert.equal(state.territory.packages.length, admittedPackages.length);
  assert.ok(state.territory.packages.length >= 281);
  assert.equal(state.territory.dependencies.length, artifact.carrierAdmissionReceipt.carrier.value.relations.filter(({ scope }) => scope === "workspace").length);
  assert.ok(state.territory.dependencies.length >= 768);
  assert.ok(state.territory.packages.every(({ id, charge, path }) => id.startsWith("package:") && charge === "potential" && path.at(-1)?.type === "node-package-manifest"));
  assert.ok(state.presentation.loci.some(({ type }) => type === "CodebaseTerritoryActorLocus"));
  assert.equal(state.presentation.territoryFoam.census["positive-bulk"], admittedPackages.length);
  assert.deepEqual(state.missionLaw, {
    type: "ModeledUnionMissionLawLocus",
    locus: "law:semiotic-foam-one-machine",
    carrierNi: "ni:///sha-256;RSyKg2hdU_EdC_L5HKXutC-PeP4Di6zsv909PElLFec",
    language: "rmn/v2",
  });
  assert.doesNotMatch(JSON.stringify(state), /Give every future human or agent entering the repository/u);
  const repeated = await handleMudApi(new Request(`https://gui.561.group/api/mud?actor=${controller}`), "read", {
    readSemioticExchangeHistory: async () => history,
    readWorkspaceTerritory: async () => artifact,
  });
  assert.equal((await repeated.json()).territory.id, state.territory.id);
});

test("the generated Worker leaks no private codebase coordinate before operator admission", async () => {
  const worker = (await import(`../src/worker.mjs?privacy=${Date.now()}`)).default;
  const response = await worker.fetch(new Request("https://gui.561.group/api/mud"), {});
  const body = await response.text();
  assert.equal(response.status, 403);
  assert.match(body, /ModeledUnionDimensionOperatorAdmissionRefusal/u);
  assert.doesNotMatch(body, /package:|package\.json|\/home\/|@red-cup-engineering/u);
});

test("the conversation endpoint inherits the fail-closed Access boundary before it can parse an utterance", async () => {
  const worker = (await import(`../src/worker.mjs?conversation-privacy=${Date.now()}`)).default;
  const response = await worker.fetch(new Request("https://gui.561.group/api/mud/conversation", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text: "do not disclose" }),
  }), {});
  const body = await response.text();
  assert.equal(response.status, 403);
  assert.match(body, /ModeledUnionDimensionOperatorAdmissionRefusal/u);
  assert.doesNotMatch(body, /do not disclose|A2A|package:|@red-cup-engineering/u);
});

test("the public face refuses invented local state when live history is not bound", async () => {
  const response = await handleMudApi(new Request("https://gui.561.group/api/mud"), "read");
  assert.equal(response.status, 503);
  assert.equal((await response.json()).type, "SemioticExchangeReadUnavailable");
});

test("the private face refuses a chain-only world without a sealed workspace territory", async () => {
  const response = await handleMudApi(new Request("https://gui.561.group/api/mud"), "read", { readSemioticExchangeHistory: async () => history });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).type, "WorkspaceTerritoryReadUnavailable");
});

test("writes report the missing zero-custody actuator instead of mutating browser state", async () => {
  const response = await handleMudApi(new Request("https://gui.561.group/api/mud/play", { method: "POST" }), "play", {});
  assert.equal(response.status, 503);
  assert.equal((await response.json()).type, "SemioticExchangeActuatorUnavailable");
});

test("an operator conversation becomes one canonical A2A/RMN request and real witnessed arena, never a browser transcript or invented chain move", async () => {
  const response = await handleMudApi(new Request("https://gui.561.group/api/mud/conversation", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ text: "Which lawful move can heal this focused territory?", locus: cell }),
  }), "conversation", {
    readSemioticExchangeHistory: async () => history,
    readWorkspaceTerritory: async () => territoryArtifact,
  });
  assert.equal(response.status, 202, await response.clone().text());
  const value = await response.json();
  assert.equal(value.type, "ModeledUnionConversationProjection");
  assert.match(value.intentNi, /^ni:\/\/\/sha-256;/u);
  assert.equal(value.a2aUserMessage.role, "ROLE_USER");
  assert.equal(value.a2aUserMessage.parts.length, 1);
  assert.equal(value.a2aUserMessage.parts[0].mediaType, "application/rmn+cbor");
  assert.equal(value.restrictedArena.type, "RestrictedModeledUnionArena");
  assert.ok(value.participants.some(({ type }) => type === "SemioticCellLocus"));
  assert.match(value.durability, /not a hidden transcript or a chain write/u);
  assert.doesNotMatch(JSON.stringify(value), /DemandRaised|chainAppend.*submitted/u);
});

test("conversation refuses an unwitnessed address rather than making a parallel locus", async () => {
  const response = await handleMudApi(new Request("https://gui.561.group/api/mud/conversation", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text: "hello", locus: "package:invented" }),
  }), "conversation", {
    readSemioticExchangeHistory: async () => history,
    readWorkspaceTerritory: async () => territoryArtifact,
  });
  assert.equal(response.status, 409);
  assert.equal((await response.json()).type, "ModeledUnionConversationRefusal");
});

function operatorRequest(token = "access-jwt") {
  return new Request("https://gui.561.group/", { headers: { "cf-access-jwt-assertion": token } });
}

test("the GUI admits only the Access application audience and exact operator identity", async () => {
  const environment = {
    ACCESS_TEAM_DOMAIN: "union.cloudflareaccess.com",
    ACCESS_POLICY_AUD: "gui-audience",
    ACCESS_OPERATOR_EMAIL: "operator@example.com",
  };
  const verifyAccessJwt = async (token, expected) => {
    assert.equal(token, "access-jwt");
    assert.deepEqual(expected, { teamDomain: "union.cloudflareaccess.com", audience: "gui-audience" });
    return { payload: { email: "Operator@Example.com" } };
  };
  assert.equal(await admitMudOperator(operatorRequest(), environment, { verifyAccessJwt }), true);
  assert.equal(await admitMudOperator(operatorRequest(), { ...environment, ACCESS_OPERATOR_EMAIL: "other@example.com" }, { verifyAccessJwt }), false);
  assert.equal(await admitMudOperator(new Request("https://gui.561.group/"), environment, { verifyAccessJwt }), false);
  assert.equal(await admitMudOperator(operatorRequest(), {}, { verifyAccessJwt }), false);
  assert.equal(await admitMudOperator(operatorRequest(), environment, { verifyAccessJwt: async () => { throw new Error("bad signature"); } }), false);
});

test("the GUI admits only the configured direct-IAP operator", async () => {
  const request = new Request("https://gui.561.group/", {
    headers: { "x-goog-authenticated-user-email": "accounts.google.com:morgan.sennhauser@gmail.com" },
  });
  assert.equal(await admitMudOperator(request, { IAP_OPERATOR_EMAIL: "morgan.sennhauser@gmail.com" }), true);
  assert.equal(await admitMudOperator(request, { IAP_OPERATOR_EMAIL: "other@example.com" }), false);
  assert.equal(await admitMudOperator(new Request("https://gui.561.group/"), { IAP_OPERATOR_EMAIL: "morgan.sennhauser@gmail.com" }), false);
});

test("the GUI admits the explicitly public projection without weakening the default boundary", async () => {
  const request = new Request("https://gui.561.group/");
  assert.equal(await admitMudOperator(request, { MUD_PUBLIC_PROJECTION: "true" }), true);
  assert.equal(await admitMudOperator(request, { MUD_PUBLIC_PROJECTION: "false" }), false);
  assert.equal(await admitMudOperator(request, {}), false);
});

test("the Worker-side reader accepts only the fixed live ledger from its VPC binding", async () => {
  const services = createCloudMudServices({ MUD_CHAIN_READER: { fetch: async (url, init) => {
    assert.equal(url, "http://semiotic-exchange-reader.internal/v1/semiotic-exchange/rpc");
    assert.equal(init.method, "POST");
    const call = JSON.parse(init.body);
    return Response.json({ jsonrpc: "2.0", id: 1, result: call.method === "eth_blockNumber" ? "0x15f3" : [] });
  } } }, territoryArtifact);
  const witnessed = await services.readSemioticExchangeHistory();
  assert.deepEqual(witnessed, []);
  assert.equal((await services.readWorkspaceTerritory()).carrierAdmissionReceipt.contentNi, territoryCarrier.contentNi);

  const malformed = createCloudMudServices({ MUD_CHAIN_READER: { fetch: async () => Response.json({ result: [] }) } });
  await assert.rejects(malformed.readSemioticExchangeHistory(), /malformed witness/u);
  await assert.rejects(createCloudMudServices().readSemioticExchangeHistory(), /not bound/u);
});
