import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { boundSolicitation, authorExactEffectOffer } from "@red-cup-engineering/deployment-formation-contracts";
import { settleReceiptVector } from "@red-cup-engineering/deployment-formation-contracts/receipt-vector";
import { assayGuiPublicDelivery } from "../scripts/assay-gui-public-delivery.mjs";

const declaration = JSON.parse(await readFile(new URL("../content/deployments/gui-public-delivery-formation.json", import.meta.url), "utf8"));
const observations = JSON.parse(await readFile(new URL("../content/deployments/gui-public-delivery-observations.json", import.meta.url), "utf8"));
const schemaProperties = ["artifactDigest", "customer", "exactEffects", "executionMode", "formationDigest", "formationType", "targetDigest", "type"];

test("GUI declaration is the exact closed-schema solicitation admitted by the formation library", () => {
  assert.deepEqual(Object.keys(declaration).sort(), schemaProperties);
  assert.equal(declaration.type, "PublicDeliverySolicitation");
  assert.equal(declaration.formationType, "PublicDeliveryFormation");
  for (const field of ["formationDigest", "artifactDigest", "targetDigest"]) assert.match(declaration[field], /^ni:\/\/\/sha-256;/u);
  const result = boundSolicitation(declaration);
  assert.equal(result.type, "DeploymentFormationStage");
  assert.equal(result.stage, "solicited");
  assert.equal(result.value.closed, true);
});

test("read-only desired state and route intent cannot masquerade as offer or effect", () => {
  const solicitation = boundSolicitation(declaration).value;
  const disguisedOffer = authorExactEffectOffer({
    solicitation,
    offer: {
      type: "ProviderExactEffectOffer",
      author: "customer-configuration",
      formationDigest: declaration.formationDigest,
      artifactDigest: declaration.artifactDigest,
      targetDigest: declaration.targetDigest,
      executionMode: declaration.executionMode,
      exactEffects: declaration.exactEffects,
      offerDigest: "ni:///sha-256;configuration-is-not-an-offer",
      observation: observations.customerConfigurationIntent
    }
  });
  assert.equal(disguisedOffer.type, "DeploymentFormationRefusal");
  assert.equal(disguisedOffer.code, "offer-not-exact");
  const disguisedEffect = settleReceiptVector({
    type: "CustomerConfigurationObservation",
    ...observations.providerApiObservation,
    formationDigest: declaration.formationDigest,
    artifactDigest: declaration.artifactDigest,
    targetDigest: declaration.targetDigest
  });
  assert.equal(disguisedEffect.type, "DeploymentFormationRefusal");
  assert.equal(disguisedEffect.code, "unbound-receipt");
  assert.equal(observations.trust.providerOffer, "absent");
  assert.equal(observations.trust.providerEffectReceipt, "absent");
});

test("independent assay reports only external DNS TLS HTTP and path observations", async () => {
  const result = await assayGuiPublicDelivery({
    resolve4: async () => ["198.51.100.10"],
    observeTls: async () => ({ check: "tls", status: "pass", code: "TLS_VALID", detail: {} }),
    fetch: async () => new Response("ok", { status: 200 })
  });
  assert.deepEqual(result.residues.map(({ check }) => check), ["dns", "tls", "http", "path"]);
  assert.equal(result.summary.pass, 4);
  assert.equal(result.summary.fail, 0);
  assert.equal(Object.hasOwn(result, "deployed"), false);
});

test("independent assay keeps external failures separate", async () => {
  const result = await assayGuiPublicDelivery({
    resolve4: async () => { throw new Error("NXDOMAIN"); },
    observeTls: async () => ({ check: "tls", status: "fail", code: "TLS_UNAVAILABLE", detail: {} }),
    fetch: async () => { throw new Error("network unavailable"); }
  });
  assert.deepEqual(result.residues.map(({ status }) => status), ["fail", "fail", "fail", "fail"]);
  assert.equal(result.residues.find(({ check }) => check === "path").code, "PATH_UNOBSERVED");
});
