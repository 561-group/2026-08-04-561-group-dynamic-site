import { createModeledUnionDimension } from "@red-cup-engineering/modeled-union-dimension";
import { readSemioticExchangeEvents } from "../../../services/red-cup-engineering/services/software-services-section/services/blockchain-services-section/services/ethereum-services-section/src/semiotic-exchange-events.mjs";
import { gyrobifastigiumJ26 } from "@lenticule-science/articulating/predicating/geometry/spatial";
import { semanticBytes, semanticId } from "@red-cup-engineering/rmn-semantic-conformance";
import { encodeRelationalValue } from "@red-cup-engineering/rmn-semantic-conformance/relational-value";
import { userRmnMessage } from "@red-cup-engineering/a2a-rmn-part-service";

export const MUD_ACTOR = "urn:ame:modeled-union-dimension";
// This browser projection is a strictly read-only witness of the live successor.
// It has no signer or append path; the retired 5615610 ledger is archive evidence.
export const MUD_LEDGER = Object.freeze({ chainId: "eip155:5615611", exchange: "0xc4234dc42c9d93bc7d61b0354aba2729ae52e322" });

const headers = Object.freeze({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
const workspaceObserverFamilies = new WeakMap();
const witnessedProjections = new WeakMap();

function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) throw new TypeError("invalid JWT base64url segment");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

function decodeJwtPart(value) {
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
}

async function readAccessJwks(teamDomain) {
  const response = await fetch(`https://${teamDomain}/cdn-cgi/access/certs`, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`Access JWKS returned HTTP ${response.status}`);
  const document = await response.json();
  if (!Array.isArray(document?.keys)) throw new TypeError("Access JWKS has no keys");
  return document.keys;
}

async function verifyAccessJwt(token, { teamDomain, audience }) {
  const segments = token.split(".");
  if (segments.length !== 3) throw new TypeError("Access assertion is not a compact JWT");
  const [protectedSegment, payloadSegment, signatureSegment] = segments;
  const protectedHeader = decodeJwtPart(protectedSegment);
  const payload = decodeJwtPart(payloadSegment);
  if (protectedHeader?.alg !== "RS256" || typeof protectedHeader.kid !== "string" || protectedHeader.kid === "") throw new TypeError("Access assertion uses an inadmissible signing key");
  const keys = await readAccessJwks(teamDomain);
  const jwk = keys.find((candidate) => candidate?.kid === protectedHeader.kid
    && candidate?.kty === "RSA" && (candidate.alg === undefined || candidate.alg === "RS256")
    && (candidate.use === undefined || candidate.use === "sig"));
  if (!jwk) throw new TypeError("Access assertion signing key is absent from the team JWKS");
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decodeBase64Url(signatureSegment), new TextEncoder().encode(`${protectedSegment}.${payloadSegment}`));
  if (!valid) throw new TypeError("Access assertion signature is invalid");
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (payload.iss !== `https://${teamDomain}` || !audiences.includes(audience)
      || typeof payload.email !== "string" || payload.email === "") {
    throw new TypeError("Access assertion claims are invalid");
  }
  return { protectedHeader, payload };
}

export async function admitMudOperator(request, environment = {}, options = {}) {
  if (environment.MUD_PUBLIC_PROJECTION === "true") return true;
  const iapOperatorEmail = String(environment.IAP_OPERATOR_EMAIL ?? "").toLowerCase();
  if (iapOperatorEmail !== "") {
    const identity = String(request.headers.get("x-goog-authenticated-user-email") ?? "").toLowerCase();
    return identity === `accounts.google.com:${iapOperatorEmail}`;
  }
  const teamDomain = String(environment.ACCESS_TEAM_DOMAIN ?? "").toLowerCase();
  const audience = String(environment.ACCESS_POLICY_AUD ?? "");
  const expectedEmail = String(environment.ACCESS_OPERATOR_EMAIL ?? "").toLowerCase();
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/u.test(teamDomain)
      || audience === "" || expectedEmail === "" || !token) return false;
  try {
    const verified = await (options.verifyAccessJwt ?? verifyAccessJwt)(token, { teamDomain, audience });
    return String(verified?.payload?.email ?? "").toLowerCase() === expectedEmail;
  } catch {
    return false;
  }
}

export function refuseUnadmittedMudOperator() {
  return json({ type: "ModeledUnionDimensionOperatorAdmissionRefusal", error: "the Access-authenticated operator on the enrolled Bare Cedar Fog device is required" }, 403);
}

export function createCloudMudServices(environment = {}, workspaceTerritoryArtifact = null) {
  const sealedWorkspaceTerritory = deepFreeze(workspaceTerritoryArtifact);
  return Object.freeze({
    async readWorkspaceTerritory() {
      if (sealedWorkspaceTerritory?.type !== "ModeledUnionWorkspaceTerritoryArtifact" || sealedWorkspaceTerritory.version !== 1) throw unavailable("the content-addressed workspace territory is not bound");
      return sealedWorkspaceTerritory;
    },
    async readSemioticExchangeHistory() {
      if (typeof environment.MUD_CHAIN_READER?.fetch !== "function") throw unavailable("the authenticated cloud chain reader is not bound");
      const rpc = async (_url, method, params) => {
        const response = await environment.MUD_CHAIN_READER.fetch("http://semiotic-exchange-reader.internal/v1/semiotic-exchange/rpc", {
          method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        });
        if (!response.ok) throw unavailable(`cloud chain reader returned HTTP ${response.status}`);
        const value = await response.json();
        if (value?.jsonrpc !== "2.0" || value?.id !== 1 || (!Object.hasOwn(value, "result") && !value.error)) throw unavailable("cloud chain reader returned a malformed witness");
        if (value.error) throw unavailable(`cloud chain reader refused: ${value.error.message ?? value.error.code ?? "unknown error"}`);
        return value.result;
      };
      const latest = BigInt(await rpc(null, "eth_blockNumber", []));
      return readSemioticExchangeEvents({
        rpcUrl: "vpc://semiotic-exchange-reader",
        exchange: MUD_LEDGER.exchange,
        fromBlock: 5619n,
        toBlock: latest,
        rpc,
      });
    },
    observeBoundaryTime() { return new Date().toISOString(); },
  });
}

function unavailable(message) { const error = new Error(message); error.status = 503; return error; }

function deepFreeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function workspaceObserverFamily(territory) {
  const prior = workspaceObserverFamilies.get(territory);
  if (prior !== undefined) return prior;
  const catalog = territory?.carrierAdmissionReceipt?.carrier?.value;
  if (catalog?.type !== "NodeWorkspaceSourceCatalogReceipt" || !Array.isArray(catalog.packages)) throw unavailable("the workspace territory carrier is malformed");
  const family = Object.freeze({
    type: "FoamObserverFamily",
    version: 1,
    observers: Object.freeze([Object.freeze({
      actor: "urn:observer:bare-cedar-fog:pnpm-workspace",
      commitments: Object.freeze(catalog.packages.map((pkg) => Object.freeze({
        locus: `package:${pkg.name}`,
        polarity: "positive",
        witnessNis: Object.freeze([pkg.manifestEvidence]),
      }))),
    })]),
  });
  workspaceObserverFamilies.set(territory, family);
  return family;
}

function eventProjectionId(event) {
  return `event:${event.chainPosition.blockNumber.toString()}:${event.chainPosition.logIndex}`;
}

function causalFlow(presentation, arena) {
  const events = presentation.events;
  const causalRelations = presentation.relations.filter(({ type }) => type === "causallyFollows");
  const locusById = new Map(presentation.loci.map((locus) => [locus.id, locus]));
  const action = ({ id, operation, available, unavailability = null, demand = null, offer = null, cell = null }) => Object.freeze({ id, operation, available, unavailability, demand, offer, cell });
  const demandThreads = events.filter(({ kind }) => kind === "DemandRaised").map((raised) => {
    const threadEvents = events.filter((event) => event.demand === raised.demand);
    const eventIds = new Set(threadEvents.map(eventProjectionId));
    const offered = threadEvents.find(({ kind }) => kind === "DemandOffered") ?? null;
    const cell = offered?.cell ?? threadEvents.find(({ kind }) => kind === "PurchaseMoved" || kind === "DemandSettled")?.cell ?? null;
    const demandLocus = locusById.get(raised.demand) ?? null;
    const cellLocus = cell === null ? null : locusById.get(cell) ?? null;
    return Object.freeze({
      demand: raised.demand,
      phase: demandLocus?.phase ?? "raised",
      charge: demandLocus?.support?.charge ?? demandLocus?.four?.charge ?? "absurd",
      raiser: raised.raiser,
      wantedLaw: raised.wantedLaw,
      grounding: raised.grounding,
      cell,
      controller: cellLocus?.controller ?? offered?.controller ?? null,
      cellPhase: cellLocus?.phase ?? null,
      events: Object.freeze(threadEvents.map((event) => Object.freeze({ id: eventProjectionId(event), kind: event.kind, chainPosition: event.chainPosition, actor: event.raiser ?? event.controller ?? null, cell: event.cell ?? null, offer: event.offer ?? null, result: event.result ?? null }))),
      causalRelations: Object.freeze(causalRelations.filter(({ from, to }) => eventIds.has(from) && eventIds.has(to)).map(({ from, to }) => Object.freeze({ from, to }))),
      restrictedJoints: Object.freeze(arena.actions.filter((candidate) => candidate.demand === raised.demand).map(action)),
    });
  });
  const cellJoints = arena.actions.filter((candidate) => candidate.cell && !candidate.demand).map(action);
  return Object.freeze({
    type: "SemioticExchangeCausalFlow",
    threads: Object.freeze(demandThreads),
    frozenJoints: Object.freeze([...demandThreads.flatMap(({ restrictedJoints }) => restrictedJoints), ...cellJoints].filter(({ available }) => !available)),
  });
}

function publicState(dimension, actor) {
  const presentation = dimension.presentation();
  const arena = dimension.restrictedArena(actor);
  const cells = presentation.loci.map((locus) => Object.freeze({ id: locus.id, charge: locus.support?.charge ?? locus.four?.charge ?? "absurd", phase: locus.phase, type: locus.type }));
  const causalEdges = presentation.relations.filter(({ type }) => type === "causallyFollows").map(({ from, to }) => Object.freeze({ from, to }));
  const eventPoints = presentation.events.map((event, index) => Object.freeze({ id: eventProjectionId(event), orientation: index % 2 }));
  const territory = presentation.territoryFoam === null ? null : Object.freeze({
    id: presentation.territoryFoam.id,
    census: presentation.territoryFoam.census,
    proofBoundary: presentation.territoryFoam.proofBoundary,
    packages: Object.freeze(presentation.territoryFoam.sections.map((section) => Object.freeze({
      id: section.locus,
      name: section.locus.slice("package:".length),
      charge: section.four.charge,
      phase: section.phase,
      path: section.witnessPath.territory.proofPath,
      manifestEvidence: section.witnessPath.territory.manifestEvidence,
      classificationReceiptNi: section.witnessPath.territory.classificationReceiptNi,
      closureOrdinal: section.convergence.closureOrdinal,
    }))),
    dependencies: presentation.territoryFoam.relations,
  });
  return Object.freeze({
    type: "ModeledUnionDimensionBrowserProjection",
    actor: dimension.actor,
    geometry: gyrobifastigiumJ26,
    embodiment: Object.freeze({
      type: "DiamondBeadJ26Embodiment",
      causalCarrier: Object.freeze({ points: eventPoints, sequencing: causalEdges }),
      beadAdjacency: Object.freeze({ thread: causalEdges, contact: causalEdges, cell: causalEdges, visible: causalEdges }),
      polarization: Object.freeze({ type: "ProperCausalColoring", colors: eventPoints.map(({ id, orientation }) => Object.freeze({ id, color: orientation })) }),
      locusGeometry: "GyrobifastigiumJ26",
    }),
    presentation,
    missionLaw: presentation.missionLaw,
    territory,
    cells,
    position: Object.freeze({ actor, locus: cells.at(-1)?.id ?? null, charge: cells.at(-1)?.charge ?? "absurd", phase: cells.at(-1)?.phase ?? "sclerotium" }),
    restrictedArena: arena,
    causalFlow: causalFlow(presentation, arena),
  });
}

function witnessedProjection(history, territory, actor) {
  let projections = witnessedProjections.get(territory);
  if (projections === undefined) {
    projections = new Map();
    witnessedProjections.set(territory, projections);
  }
  const historyKey = history.map((event) => `${event.kind}:${event.chainPosition.blockNumber}:${event.chainPosition.logIndex}:${event.carrierNi}`).join("|");
  const key = `${actor}\n${historyKey}`;
  const prior = projections.get(key);
  if (prior !== undefined) return prior;
  const dimension = createModeledUnionDimension({
    events: history,
    carrierAdmissions: [territory.carrierAdmissionReceipt],
    observerFamily: workspaceObserverFamily(territory),
    missionLaw: territory.observationReceipt?.missionLaw ?? null,
    ...MUD_LEDGER,
  });
  const projection = publicState(dimension, actor);
  projections.clear();
  projections.set(key, projection);
  return projection;
}

function canonical(value) {
  const encoded = encodeRelationalValue(value);
  const term = ["ascribe", encoded.type, encoded.term];
  return Object.freeze({ bytes: semanticBytes(term), ni: semanticId(term) });
}

/**
 * Turn one Access-admitted operator utterance into the existing A2A/RMN
 * carrier, while refusing to pretend that a browser request was a chain append
 * or a durable conversation. The returned restricted arena is read afresh from
 * witnessed history, so a conversation is a real request for lawful moves.
 */
async function admitConversation(request, services) {
  let input;
  try { input = await request.json(); } catch { return json({ type: "ModeledUnionConversationRefusal", error: "one JSON conversation request is required" }, 400); }
  const text = typeof input?.text === "string" ? input.text.trim() : "";
  if (text.length < 1 || text.length > 4096) return json({ type: "ModeledUnionConversationRefusal", error: "conversation text must contain 1 through 4096 Unicode code units" }, 400);
  if (typeof services.readSemioticExchangeHistory !== "function" || typeof services.readWorkspaceTerritory !== "function") return json({ type: "ModeledUnionConversationRefusal", error: "the live witnessed dimension is unavailable" }, 503);
  const actor = typeof input.actor === "string" && input.actor.length > 0 ? input.actor : "0x0000000000000000000000000000000000000000";
  const history = await services.readSemioticExchangeHistory();
  const territory = deepFreeze(await services.readWorkspaceTerritory());
  const projection = witnessedProjection(history, territory, actor);
  const availableLoci = new Set([
    ...projection.cells.map(({ id }) => id),
    ...projection.territory.packages.map(({ id }) => id),
    ...(projection.missionLaw?.locus ? [projection.missionLaw.locus] : []),
  ]);
  const locus = typeof input.locus === "string" && input.locus.length > 0 ? input.locus : projection.cells.at(-1)?.id;
  if (!availableLoci.has(locus)) return json({ type: "ModeledUnionConversationRefusal", error: "the addressed locus is not currently witnessed in this private dimension" }, 409);
  const intent = canonical({
    type: "ModeledUnionConversationIntent",
    version: 1,
    actor,
    locus,
    text,
    territory: projection.territory.id,
    missionLaw: projection.missionLaw?.carrierNi ?? null,
    causalPredecessors: projection.presentation.events.map((event) => `event:${event.chainPosition.blockNumber}:${event.chainPosition.logIndex}`),
    restrictedArena: projection.restrictedArena.actions.map(({ id, operation, available, unavailability = null }) => ({ id, operation, available, unavailability })),
  });
  const message = userRmnMessage(intent.bytes, "modeled-union-conversation.rmn.cbor");
  const receipt = canonical({
    type: "ModeledUnionConversationAdmissionReceipt",
    version: 1,
    disposition: "admitted-ephemeral-request",
    intentNi: intent.ni,
    a2aMessageId: message.messageId,
    a2aPartNi: message.parts[0].metadata.ni,
    chainAppend: "not-requested",
    durability: "none-until-an-enabled-restricted-move-is-explicitly-actuated",
  });
  return json({
    type: "ModeledUnionConversationProjection",
    receiptNi: receipt.ni,
    intentNi: intent.ni,
    a2aUserMessage: message,
    locus,
    participants: projection.presentation.loci.map(({ id, type, phase, controller, law, support }) => ({ id, type, phase, controller: controller ?? null, law: law ?? null, charge: support?.charge ?? "absurd" })),
    restrictedArena: projection.restrictedArena,
    causalFollowups: projection.presentation.relations.filter(({ type }) => type === "causallyFollows"),
    durability: "This is an A2A/RMN boundary admission, not a hidden transcript or a chain write. Select an enabled restricted move to request an actuator.",
  }, 202);
}

export async function handleMudApi(request, endpoint, services = {}) {
  try {
    const method = endpoint === "read" ? "GET" : endpoint === "play" || endpoint === "conversation" ? "POST" : null;
    if (method === null) return json({ error: "unknown MUD endpoint" }, 404);
    if (request.method === "OPTIONS") return preflight(method);
    if (request.method !== method) return methodNotAllowed(method);
    if (endpoint === "play") return json({ type: "SemioticExchangeActuatorUnavailable", error: "the zero-custody SemioticExchange append actuator is unavailable" }, 503);
    if (endpoint === "conversation") return admitConversation(request, services);
    if (typeof services.readSemioticExchangeHistory !== "function") return json({ type: "SemioticExchangeReadUnavailable", error: "a live SemioticExchange history source is not bound" }, 503);
    const url = new URL(request.url);
    const actor = url.searchParams.get("actor") ?? "0x0000000000000000000000000000000000000000";
    const history = await services.readSemioticExchangeHistory();
    if (typeof services.readWorkspaceTerritory !== "function") return json({ type: "WorkspaceTerritoryReadUnavailable", error: "a content-addressed workspace territory is not bound" }, 503);
    const territory = deepFreeze(await services.readWorkspaceTerritory());
    return json(witnessedProjection(history, territory, actor));
  } catch (error) {
    const status = Number.isInteger(error?.status) ? error.status : 400;
    return json({ error: error instanceof Error ? error.message : String(error) }, status);
  }
}

function preflight(method) {
  return new Response(null, { status: 204, headers: { "access-control-allow-methods": `${method}, OPTIONS`, allow: `${method}, OPTIONS`, "cache-control": "private, max-age=86400" } });
}

function methodNotAllowed(method) {
  return new Response(JSON.stringify({ error: "method not allowed" }), { status: 405, headers: { ...headers, allow: `${method}, OPTIONS` } });
}

function json(value, status = 200) { return new Response(JSON.stringify(value, (_key, entry) => typeof entry === "bigint" ? entry.toString() : entry), { status, headers }); }

const BASE_MUD_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>Semiotic Foam · 561 Group</title><meta name="description" content="A live ledger-derived Modeled Union Dimension.">
<style>
:root{color-scheme:dark;--ink:#f2ead8;--dim:#a89e88;--void:#090b0f;--panel:#11151bdd;--line:#415260;--gold:#e7bd63;--potential:#ff708f;--active:#58e5a7;--absurd:#8b9ca8;--stable:#ffd369}*{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--void);color:var(--ink);font:15px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace}#foam{position:fixed;inset:0;width:100%;height:100%;display:block;cursor:grab;touch-action:none}#foam:active{cursor:grabbing}#hud{position:fixed;inset:0;pointer-events:none}#hud>*{pointer-events:auto}.panel{background:var(--panel);border:1px solid var(--line);border-radius:11px;box-shadow:0 12px 42px #0009;backdrop-filter:blur(10px)}#title{position:absolute;top:18px;left:18px;padding:12px 15px;max-width:min(510px,calc(100vw - 36px))}.eyebrow,.label{color:var(--dim);text-transform:uppercase;letter-spacing:.13em;font-size:.68rem}h1{margin:3px 0 0;font:600 clamp(1.55rem,4vw,3.3rem)/.95 Georgia,serif;letter-spacing:-.04em}.sub{margin:8px 0 0;color:#c3b9a8;font-size:.78rem}.charge-key{position:absolute;right:18px;bottom:18px;padding:9px 11px;font-size:.75rem;color:var(--dim);display:grid;gap:3px}.charge-key b{font-size:1rem}.potential{color:var(--potential)}.active{color:var(--active)}.absurd{color:var(--absurd)}.stable{color:var(--stable)}#vitals{position:absolute;left:18px;bottom:18px;padding:12px;min-width:260px}.charge{font:700 2.2rem/1 Georgia,serif;color:var(--gold)}.locus{margin-top:2px;font-size:1.05rem;color:var(--ink);overflow-wrap:anywhere}.minor{margin-top:4px;color:var(--dim);font-size:.76rem}#territory{position:absolute;right:18px;top:18px;width:min(410px,calc(100vw - 36px));padding:12px;max-height:54vh;overflow:auto}#frontier{position:absolute;right:18px;bottom:118px;width:min(410px,calc(100vw - 36px));padding:12px;max-height:28vh;overflow:auto}h2{margin:0;font-size:.8rem;text-transform:uppercase;letter-spacing:.12em;color:var(--dim)}#actions{margin-top:8px}input{width:100%;margin-top:9px;padding:9px 10px;border:1px solid #536875;border-radius:7px;background:#091117;color:var(--ink);font:inherit}button{display:grid;grid-template-columns:1fr auto;align-items:center;gap:4px 9px;width:100%;margin-top:6px;padding:10px;border:1px solid #536875;border-radius:7px;background:#17242d;color:var(--ink);font:inherit;text-align:left;cursor:pointer}button:hover,button:focus-visible,button.selected{border-color:var(--gold);background:#263640}button kbd{color:var(--gold);font:inherit}.detail{grid-column:1/-1;color:var(--dim);font-size:.7rem;overflow-wrap:anywhere}#packages{margin-top:7px;display:grid;gap:4px}.package{padding:7px 8px}.package .symbol{color:var(--gold)}#proof{margin-top:9px;padding-top:8px;border-top:1px solid var(--line);font-size:.72rem;color:var(--dim);overflow-wrap:anywhere}#ledger{position:absolute;left:18px;bottom:124px;width:min(430px,calc(100vw - 36px));padding:12px;max-height:30vh;overflow:auto}#events{margin-top:7px;display:grid;gap:5px;font-size:.78rem}.event{padding-left:8px;border-left:2px solid #546570;color:#c8c2b6}.event.latest{border-color:var(--active);color:#b5ecd4}.event.error{border-color:var(--potential);color:#ffb1c2}.event strong{color:var(--ink)}.flow{padding:8px;border-left:2px solid var(--gold);background:#0d1419}.flow .steps{color:#b5ecd4;overflow-wrap:anywhere}.flow .joint{margin-top:4px;color:var(--dim);font-size:.7rem}.flow .frozen{color:#ffb1c2}#hint{position:absolute;left:50%;bottom:18px;transform:translateX(-50%);padding:8px 11px;color:var(--dim);font-size:.72rem;text-align:center}@media(max-width:700px){#territory{max-height:46vh}#frontier{display:none}#ledger{display:none}#title{max-width:calc(100vw - 36px);right:18px}#title .sub{display:none}#hint,.charge-key{display:none}}
</style></head><body><canvas id="foam" aria-label="Exact J26 geometry of the witnessed Modeled Union Dimension"></canvas><div id="hud"><section id="title" class="panel"><div class="eyebrow">Miaotang · semantics · mathematics ／ Jianghu · syntax · standards</div><h1>Semiotic Foam</h1><p class="sub">Walk the content-addressed codebase territory and its live Semiotic Exchange pressure. Geometry embodies witnessed loci; it does not invent them.</p></section><section id="vitals" class="panel"><div class="label">Focused locus</div><div id="charge" class="charge">·</div><div id="locus" class="locus">germinating…</div><div id="phase" class="minor">reading the private territory</div></section><section id="territory" class="panel"><h2>Codebase territory · proof paths</h2><input id="package-search" type="search" placeholder="Find a package locus…" autocomplete="off"><div id="territory-count" class="minor"></div><div id="packages"></div><div id="proof"></div></section><section id="frontier" class="panel"><h2>Restricted arena · dependency neighborhood</h2><div id="actions"></div></section><section id="ledger" class="panel"><h2>Witnessed causal demand flow</h2><div id="events" aria-live="polite"></div></section><div id="hint" class="panel">select a package, then drag its J26 dependency neighborhood</div><aside class="charge-key panel" aria-label="FOUR charge legend"><span><b class="absurd">⊥</b> absurd / neither</span><span><b class="potential">t</b> potential / true only</span><span><b class="active">f</b> active / false only</span><span><b class="stable">⊤</b> stable / both</span></aside></div><script src="/mud-client.js" defer></script></body></html>`;

const BASE_MUD_CLIENT = `(()=>{'use strict';
const $=s=>document.querySelector(s),canvas=$('#foam'),ctx=canvas.getContext('2d'),locus=$('#locus'),charge=$('#charge'),phase=$('#phase'),actions=$('#actions'),events=$('#events'),search=$('#package-search'),packages=$('#packages'),proof=$('#proof'),territoryCount=$('#territory-count');
let state,focusId=null,visible=[],ay=-.55,ax=.42,drag=null,lastError='';
const palette={absurd:['#8b9ca8','#34414a','⊥'],potential:['#ff708f','#792b45','t'],active:['#58e5a7','#176747','f'],stable:['#ffd369','#9e5f25','⊤']};
function resize(){const d=Math.min(devicePixelRatio||1,2),r=canvas.getBoundingClientRect();canvas.width=r.width*d;canvas.height=r.height*d;ctx.setTransform(d,0,0,d,0,0);draw()}
function rot(v){let[x,y,z]=v,cy=Math.cos(ay),sy=Math.sin(ay),cx=Math.cos(ax),sx=Math.sin(ax),X=x*cy+z*sy,Z=-x*sy+z*cy;return[X,y*cx-Z*sx,y*sx+Z*cx]}
function neighborhood(id){if(!state?.territory)return[];const related=new Set([id]);state.territory.dependencies.forEach(e=>{if(e.from===id)related.add(e.to);if(e.to===id)related.add(e.from)});return [...related].slice(0,11).map(key=>state.territory.packages.find(p=>p.id===key)).filter(Boolean)}
function shortName(id){const name=id.startsWith('package:')?id.slice(8):id;return name.startsWith('@')?name.slice(name.indexOf('/')+1):name}
function draw(){if(!state)return;const cells=visible.length?visible:state.cells.slice(-3),w=canvas.clientWidth,h=canvas.clientHeight,s=Math.min(w/Math.max(8,cells.length*2.25),h/4.5),mesh=state.geometry,faces=[];ctx.clearRect(0,0,w,h);ctx.fillStyle='#090b0f';ctx.fillRect(0,0,w,h);cells.forEach((cell,i)=>{const off=(i-(cells.length-1)/2)*2.25;mesh.faces.forEach((face,fi)=>{const pts=face.vertices.map(n=>{const p=rot(mesh.vertices[n]);return{x:w/2+(p[0]+off)*s,y:h/2-p[1]*s,z:p[2]}});faces.push({pts,z:pts.reduce((a,p)=>a+p.z,0)/pts.length,cell,fi,current:cell.id===focusId})})});faces.sort((a,b)=>a.z-b.z).forEach(f=>{const colors=palette[f.cell.charge]||palette.absurd;ctx.beginPath();f.pts.forEach((p,i)=>i?ctx.lineTo(p.x,p.y):ctx.moveTo(p.x,p.y));ctx.closePath();ctx.fillStyle=colors[f.fi<4?0:1];ctx.globalAlpha=f.current?.96:.56;ctx.fill();ctx.globalAlpha=1;ctx.strokeStyle=f.current?'#fff3bd':'#1b2932';ctx.lineWidth=f.current?2.8:1;ctx.stroke()});cells.forEach((cell,i)=>{const x=w/2+(i-(cells.length-1)/2)*2.25*s;ctx.fillStyle=cell.id===focusId?'#fff3bd':'#c9c1b0';ctx.textAlign='center';ctx.font=(cell.id===focusId?'700 ':'')+'11px ui-monospace';ctx.fillText(shortName(cell.id).slice(0,24),x,h/2+1.55*s);ctx.fillStyle=(palette[cell.charge]||palette.absurd)[0];ctx.font='700 15px Georgia';ctx.fillText((palette[cell.charge]||palette.absurd)[2],x,h/2+1.78*s)})}
function focus(id){const p=state.territory.packages.find(x=>x.id===id);if(!p)return;focusId=id;visible=neighborhood(id);const color=palette[p.charge]||palette.absurd;charge.textContent=color[2];charge.style.color=color[0];locus.textContent=p.name;phase.textContent=p.phase+' · closure ordinal '+p.closureOrdinal.value;proof.textContent='CHL restriction: '+p.path.map(step=>step.type).join(' ⊢ ')+' · manifest '+p.manifestEvidence;renderDependencies();renderPackages();draw()}
function renderDependencies(){actions.replaceChildren();const edges=state.territory.dependencies.filter(e=>e.from===focusId||e.to===focusId);edges.slice(0,24).forEach(e=>{const target=e.from===focusId?e.to:e.from,b=document.createElement('button');b.type='button';b.innerHTML='<span>'+shortName(target)+'</span><span class="detail">'+(e.from===focusId?'requires':'required by')+' · '+e.role+' · '+e.requested+'</span>';b.onclick=()=>focus(target);actions.append(b)});if(!edges.length){const el=document.createElement('div');el.className='event';el.textContent='This admitted package has no internal dependency arrows.';actions.append(el)}}
function renderPackages(){const q=search.value.trim().toLowerCase(),matches=state.territory.packages.filter(p=>!q||p.name.toLowerCase().includes(q)).slice(0,18);packages.replaceChildren();matches.forEach(p=>{const b=document.createElement('button');b.type='button';b.className='package'+(p.id===focusId?' selected':'');b.innerHTML='<span><span class="symbol">'+(palette[p.charge]||palette.absurd)[2]+'</span> '+p.name+'</span><span class="detail">'+p.phase+'</span>';b.onclick=()=>focus(p.id);packages.append(b)});territoryCount.textContent=state.territory.packages.length+' admitted packages · '+state.territory.dependencies.length+' internal arrows · law '+state.missionLaw.carrierNi}
function eventText(r){return r.kind+' · block '+r.chainPosition.blockNumber+':'+r.chainPosition.logIndex}
function renderLedger(){events.replaceChildren();const flow=state?.causalFlow;if(!flow?.threads?.length){const el=document.createElement('div');el.className='event';el.textContent='No witnessed demand thread in the bounded history.';events.append(el)}(flow?.threads||[]).slice(-8).forEach(thread=>{const el=document.createElement('div'),title=document.createElement('strong'),steps=document.createElement('div'),parties=document.createElement('div'),joints=thread.restrictedJoints||[];el.className='flow';title.textContent=thread.phase+' demand · '+thread.demand.slice(0,18)+'…';steps.className='steps';steps.textContent=thread.events.map(eventText).join(' → ');parties.className='joint';parties.textContent='raiser '+thread.raiser+' · controller '+(thread.controller||'unassigned')+' · cell '+(thread.cell||'unassigned');el.append(title,steps,parties);joints.forEach(joint=>{const line=document.createElement('div');line.className='joint '+(joint.available?'':'frozen');line.textContent=(joint.available?'enabled ':'frozen ')+joint.operation+(joint.unavailability?' · '+joint.unavailability:'');el.append(line)});events.append(el)});const frozen=flow?.frozenJoints||[];if(frozen.length&&!flow?.threads?.length){const el=document.createElement('div');el.className='event error';el.textContent=frozen.length+' witnessed restricted joints are frozen.';events.append(el)}if(lastError){const el=document.createElement('div');el.className='event error';el.textContent=lastError;events.append(el)}}
function render(){if(!state.territory)throw new Error('the MUD returned no admitted workspace territory');renderLedger();search.addEventListener('input',renderPackages);const preferred=state.territory.packages.find(p=>p.name==='@561-group/561.group')||state.territory.packages[0];focus(preferred.id)}
async function load(){const r=await fetch('/api/mud',{headers:{accept:'application/json'}});if(!r.ok)throw new Error('unable to witness the private dimension');state=await r.json();render()}
canvas.addEventListener('pointerdown',e=>{drag=[e.clientX,e.clientY];canvas.setPointerCapture(e.pointerId)});canvas.addEventListener('pointermove',e=>{if(!drag)return;ay+=(e.clientX-drag[0])*.009;ax+=(e.clientY-drag[1])*.009;drag=[e.clientX,e.clientY];draw()});canvas.addEventListener('pointerup',()=>drag=null);addEventListener('resize',resize);load().then(resize).catch(e=>{lastError=e.message;renderLedger()})})();`;

export const MUD_HTML = BASE_MUD_HTML.replace(
  '<div id="hint" class="panel">',
  '<section id="conversation" class="panel"><h2>Speak to the witnessed swarm</h2><div class="minor">Your words become one canonical RMN A2A user message addressed to the focused locus. They are not a hidden transcript or an invented chain event.</div><textarea id="swarm-message" maxlength="4096" placeholder="Name a pressure, question, or lawful next move…"></textarea><button id="send-swarm-message" type="button"><span>Form conversation move</span><kbd>↵</kbd></button><div id="conversation-status" aria-live="polite">Select a locus, then articulate one demand.</div></section><div id="hint" class="panel">',
).replace(
  '</style>',
  '#conversation{position:absolute;left:18px;top:178px;width:min(430px,calc(100vw - 36px));padding:12px;max-height:34vh;overflow:auto}#conversation textarea{display:block;width:100%;min-height:68px;margin-top:8px;resize:vertical;padding:9px 10px;border:1px solid #536875;border-radius:7px;background:#091117;color:var(--ink);font:inherit}#conversation-status{margin-top:8px;color:var(--dim);font-size:.72rem;overflow-wrap:anywhere}@media(max-width:700px){#conversation{top:auto;bottom:16px;max-height:32vh}}</style>',
);

export const MUD_CLIENT = `${BASE_MUD_CLIENT}
;(()=>{'use strict';
const text=document.querySelector('#swarm-message'),send=document.querySelector('#send-swarm-message'),status=document.querySelector('#conversation-status');
if(!text||!send||!status)return;
async function converse(){const body=text.value.trim();if(!body)return;const focused=document.querySelector('#locus')?.textContent;send.disabled=true;status.textContent='articulating a canonical RMN/A2A request…';try{const r=await fetch('/api/mud/conversation',{method:'POST',headers:{'content-type':'application/json',accept:'application/json'},body:JSON.stringify({text:body,locus:focused?.startsWith('@')?'package:'+focused:undefined})});const value=await r.json();if(!r.ok)throw new Error(value.error||value.type||'conversation refusal');text.value='';const actions=value.restrictedArena?.actions||[];const available=actions.filter(a=>a.available).length,statuses=value.participants?.length||0;status.textContent='admitted '+value.intentNi+' · '+statuses+' witnessed participants · '+available+' enabled next moves · '+value.durability}catch(error){status.textContent='refused: '+error.message}finally{send.disabled=false}}
send.addEventListener('click',converse);text.addEventListener('keydown',event=>{if((event.ctrlKey||event.metaKey)&&event.key==='Enter'){event.preventDefault();converse()}})})();`;
