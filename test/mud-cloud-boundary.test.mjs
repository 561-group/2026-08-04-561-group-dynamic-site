import assert from "node:assert/strict";
import test from "node:test";
import { MUD_CHAIN, MUD_EXCHANGE, reconcileMudCloudBoundary } from "../src/mud-cloud-boundary.mjs";

const receipt = (id, extra = {}) => ({ id: `urn:sha256:${id.repeat(64)}`, ...extra });
function evidence() { return {
  deploymentManifest: receipt("a", { chain: { caip2: MUD_CHAIN }, contracts: [{ contractName: "SemioticExchange", address: MUD_EXCHANGE, runtimeBytecodeHash: `0x${"1".repeat(64)}` }] }),
  reconciliationReceipt: receipt("b", { chainId: MUD_CHAIN, exchange: MUD_EXCHANGE, finalized: true }),
  carrierAdmissionBinding: receipt("c", { authority: "bound", carrier: { type: "ActivityPubCloudEventA2aRmnCarrierAdmission" } }),
  zeroCustodyTransitionBinding: receipt("d", { authority: "bound", custody: "zero" }),
  expectedRevision: "gui-7", cloudRunReceipt: receipt("e", { revision: "gui-7", health: "healthy" }),
  cloudflareBinding: receipt("f", { vpc: "bound", access: "bound", dns: "bound" }),
}; }
test("complete commuting evidence enables exact forwarding idempotently", () => { const input = evidence(); assert.deepEqual(reconcileMudCloudBoundary(input), reconcileMudCloudBoundary(input)); assert.equal(reconcileMudCloudBoundary(input).enabled, true); });
for (const [name, change] of [["stale revision", (x) => { x.cloudRunReceipt.revision = "old"; }], ["wrong chain", (x) => { x.deploymentManifest.chain.caip2 = "eip155:5615610"; }], ["wrong address", (x) => { x.deploymentManifest.contracts[0].address = "0x0000000000000000000000000000000000000000"; }], ["incomplete carrier", (x) => { x.carrierAdmissionBinding.carrier.type = "CloudEvent"; }], ["forged authority", (x) => { x.zeroCustodyTransitionBinding.authority = "forged"; }]]) test(name + " obstructs", () => { const input = evidence(); change(input); assert.equal(reconcileMudCloudBoundary(input).type, "MudCloudBoundaryObstruction"); });
