import { renderWebGuiDocument } from "@red-cup-engineering/web-gui-services-section";
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
        // The successor SemioticExchange was deployed on the new chain; its
        // bounded history begins at genesis rather than the retired chain's cut.
        fromBlock: 0n,
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
  const text = typeof input?.text === "string" ? input.text.trim() : typeof input?.utterance === "string" ? input.utterance.trim() : "";
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

export function projectMudWebGui(projection) {
  const packages=projection.territory?.packages??[],side=Math.max(1,Math.ceil(Math.sqrt(packages.length))),four=v=>v==="absurd"?"unknown":["potential","active","stable"].includes(v)?v:"unknown";
  const entities=packages.map((e,i)=>({id:e.id,name:e.name,kind:"package-locus",charge:four(e.charge),position:{x:i%side-side/2,y:Math.floor(i/side)-side/2,z:Number(e.closureOrdinal?.value??0)%4/3},height:.65+Math.min(2.8,(e.path?.length??1)/3),detail:e.phase+" · "+(e.path??[]).map(s=>s.type).join(" ⊢ "),witness:e.manifestEvidence??""}));
  const ids=new Set(entities.map(e=>e.id)),paths=(projection.territory?.dependencies??[]).filter(e=>ids.has(e.from)&&ids.has(e.to)).map(e=>({from:e.from,to:e.to,charge:e.role==="dependency"?"potential":"active"})),preferred=packages.find(e=>e.name==="@561-group/561.group")??packages[0]??{},threads=projection.causalFlow?.threads??[],frozen=projection.causalFlow?.frozenJoints??[];
  const journal=threads.slice(-8).map(e=>({id:e.demand,tone:e.phase==="settled"?"success":e.restrictedJoints?.some(j=>!j.available)?"contradiction":"notice",summary:e.phase+" demand · "+e.demand,detail:(e.events??[]).map(x=>x.kind).join(" → ")}));if(!journal.length&&frozen.length)journal.push({id:"frozen-joints",tone:"contradiction",summary:frozen.length+" restricted joints remain frozen.",detail:"The obstruction is retained instead of painted as success."});
  return {kind:"web-gui.world-projection",revision:projection.territory?.id??projection.missionLaw?.carrierNi??"unwitnessed",title:"The Ceramic Jianghu",subtitle:"A playable local restriction of the witnessed Modeled Union — porous where unknown, cracked where both accounts remain.",actor:{id:projection.actor??"urn:ame:modeled-union-dimension",name:"Waste-Stream Wanderer",condition:frozen.length?frozen.length+" held knots":"confluent"},locus:{id:preferred.id??"nowhere",name:preferred.name??"Unresolved locus",description:preferred.phase??"No admitted package locus."},entities,paths,actions:(projection.restrictedArena?.actions??[]).slice(0,9).map((e,i)=>({id:e.operation+"-"+i,label:e.operation,detail:e.unavailability??"Admitted restricted move",command:e.operation,enabled:e.available===true,shortcut:String(i+1)})),journal,faculties:[{id:"perception",name:"Perception",level:Math.min(100,Math.round(packages.length/4)),voice:packages.length+" admitted package loci are visible.",active:true},{id:"causality",name:"Causal Memory",level:Math.min(100,threads.length*14),voice:threads.length+" ordered demand threads."},{id:"composure",name:"Composure",level:Math.max(0,100-frozen.length*8),voice:frozen.length?"Do not sand the contradiction out of the ceramic.":"The local joints settle."}],contradictions:frozen.map((e,i)=>({id:e.id??"frozen-"+i,summary:e.unavailability??"A restricted joint is frozen.",witnesses:[e.operation].filter(Boolean),retained:true})),witness:{status:"live",receipt:projection.territory?.id??projection.missionLaw?.carrierNi??""}};
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
    const projection = witnessedProjection(history, territory, actor);
    return json(url.searchParams.get("view") === "web-gui" ? projectMudWebGui(projection) : projection);
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

const EMPTY_WEB_GUI_MODEL={title:"The Ceramic Jianghu",subtitle:"Germinating a local witnessed projection…",actor:{id:"urn:ame:modeled-union-dimension",name:"Waste-Stream Wanderer",condition:"attending"},locus:{id:"germinating",name:"Unresolved locus",description:"Reading the admitted territory."},entities:[],paths:[],actions:[],journal:[],faculties:[],witness:{status:"unwitnessed"}};
export const MUD_HTML=renderWebGuiDocument(EMPTY_WEB_GUI_MODEL,{documentTitle:"The Ceramic Jianghu · 561 Group",source:"/api/mud?view=web-gui",actionEndpoint:"/api/mud/conversation"});
export const MUD_CLIENT="";
