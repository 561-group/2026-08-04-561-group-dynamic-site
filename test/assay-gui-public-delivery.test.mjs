import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { assayGuiPublicDelivery, observeTls } from "../scripts/assay-gui-public-delivery.mjs";

const formation = JSON.parse(await readFile(new URL("../content/deployments/gui-public-delivery-formation.json", import.meta.url), "utf8"));

test("formation binds the current desired Cloud Run image and declared Wrangler route", () => {
  const cloudRun = formation.providerExactEffectOffers.find((offer) => offer.provider === "Google Cloud Run");
  assert.equal(cloudRun.latestReadyRevision, "wuxian-gui-00006-trb");
  assert.match(cloudRun.image, /@sha256:34c7581c8b8cb31032b317a6378bebb7752067e3edcbc49e490f0032a69ec895$/u);
  assert.equal(formation.providerExactEffectOffers[1].routes[2].pattern, "gui.561.group");
  assert.equal(formation.admission.status, "unsettled");
  assert.deepEqual(formation.independentAssayVector.residueKinds, ["pass", "fail", "not-claimed", "not-applicable"]);
});

test("independent assay separates observations without a deployment assertion", async () => {
  const result = await assayGuiPublicDelivery({
    formation,
    resolve4: async () => ["198.51.100.10"],
    observeTls: async () => ({ check: "tls", status: "pass", code: "TLS_VALID", detail: {} }),
    fetch: async () => new Response("ok", { status: 200 })
  });
  assert.equal(result.summary.pass, 4);
  assert.equal(result.summary.fail, 0);
  assert.equal(result.residues.find((item) => item.check === "access-policy").status, "not-claimed");
  assert.equal(result.residues.find((item) => item.check === "provider-effect").status, "not-applicable");
  assert.equal(Object.hasOwn(result, "deployed"), false);
});

test("independent assay reports DNS and HTTP failures independently", async () => {
  const result = await assayGuiPublicDelivery({
    formation,
    resolve4: async () => { throw new Error("NXDOMAIN"); },
    observeTls: async () => ({ check: "tls", status: "fail", code: "TLS_UNAVAILABLE", detail: {} }),
    fetch: async () => { throw new Error("network unavailable"); }
  });
  assert.equal(result.residues.find((item) => item.check === "dns").status, "fail");
  assert.equal(result.residues.find((item) => item.check === "http").status, "fail");
  assert.equal(result.residues.find((item) => item.check === "path").code, "PATH_UNOBSERVED");
});
