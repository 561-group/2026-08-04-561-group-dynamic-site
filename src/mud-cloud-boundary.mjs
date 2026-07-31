export const MUD_CHAIN = "eip155:5615611";
export const MUD_EXCHANGE = "0xc4234dc42c9d93bc7d61b0354aba2729ae52e322";

function obstruction(reason) {
  return Object.freeze({ type: "MudCloudBoundaryObstruction", version: 1, status: 503, reason });
}

function receipt(value, name) {
  if (value === null || typeof value !== "object" || typeof value.id !== "string" || value.id === "") throw new Error(`${name} receipt is absent`);
  return value;
}

/** Pure reconciler: only exact, receipted coordinates enable the GUI pore. */
export function reconcileMudCloudBoundary(input) {
  try {
    if (input === null || typeof input !== "object") return obstruction("membrane evidence is absent");
    const manifest = receipt(input.deploymentManifest, "deployment manifest");
    if (manifest.chain?.caip2 !== MUD_CHAIN || manifest.contracts?.some((entry) => entry.address === "unknown" || entry.runtimeBytecodeHash === "unknown")) return obstruction("deployment manifest is not a verified deployment on the configured MUD_CHAIN");
    const exchange = manifest.contracts?.find((entry) => entry.contractName === "SemioticExchange" || entry.standard === "org.emsenn.evm.semiotic-exchange.v1");
    if (exchange?.address?.toLowerCase() !== MUD_EXCHANGE) return obstruction("deployment manifest has the wrong exchange address");
    const reconciliation = receipt(input.reconciliationReceipt, "finalized indexer reconciliation");
    if (reconciliation.chainId !== MUD_CHAIN || reconciliation.exchange?.toLowerCase() !== MUD_EXCHANGE || reconciliation.finalized !== true) return obstruction("indexer reconciliation is incomplete or stale");
    const carrier = receipt(input.carrierAdmissionBinding, "carrier admission binding");
    if (carrier.carrier?.type !== "ActivityPubCloudEventA2aRmnCarrierAdmission" || carrier.authority !== "bound") return obstruction("ActivityPub(CloudEvent(A2A(RMN))) carrier admission is incomplete");
    const transition = receipt(input.zeroCustodyTransitionBinding, "zero-custody transition binding");
    if (transition.authority !== "bound" || transition.custody !== "zero") return obstruction("zero-custody transition binding is incomplete");
    const run = receipt(input.cloudRunReceipt, "Cloud Run");
    if (run.revision !== input.expectedRevision || run.health !== "healthy") return obstruction("Cloud Run revision or health is stale");
    const edge = receipt(input.cloudflareBinding, "Cloudflare");
    if (edge.vpc !== "bound" || edge.access !== "bound" || edge.dns !== "bound") return obstruction("Cloudflare VPC, Access, or DNS binding is incomplete");
    return Object.freeze({ type: "ModeledUnionDimensionGuiBoundary", version: 3, hostname: "gui.561.group", chainId: MUD_CHAIN, exchange: MUD_EXCHANGE, route: "/api/mud/play", enabled: true, receipts: Object.freeze([manifest.id, reconciliation.id, carrier.id, transition.id, run.id, edge.id]) });
  } catch (error) { return obstruction(error instanceof Error ? error.message : String(error)); }
}

export function mudBoundaryFromEnvironment(environment) {
  const raw = environment.MUD_MEMBRANE_EVIDENCE;
  if (raw === undefined || raw === null) return reconcileMudCloudBoundary(null);
  try { return reconcileMudCloudBoundary(typeof raw === "string" ? JSON.parse(raw) : raw); } catch { return obstruction("membrane evidence is malformed"); }
}
