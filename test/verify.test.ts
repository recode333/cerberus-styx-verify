// Tests of the verify package. Self-contained: they import only this package
// and the public vectors next to them.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { generateKeyPairSync, sign } from "node:crypto";

import {
  canonicalizarRfc,
  mensajeAceptacionBloqueoMoira,
  mensajeDeclaracionReferencia,
  mensajeReciboFirmado,
  textoAceptacionBloqueoMoira,
  verificarAceptacionBloqueoMoira,
  claveBloqueoMoira,
  claveIntento,
  claveRevelacionMoira,
  claveSalMoira,
  compromisoSalMoira,
  etiquetaDuenoSalMoira,
  idDespliegueStyx,
  keccak256Hex,
  LectorTestigoStyx,
  SELECTOR_GET_ONE_ENTRY_LOG,
  serializarJcs,
  verificarDeclaracionReferencia,
  verificarRecibo,
  type CadenaLecturaStyx,
  type CadenaTestigo,
} from "../src/index.ts";

const V = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8"));

test("SV-01 keccak256 and RFC 8785 match the public vectors", () => {
  assert.equal(keccak256Hex(""), V.keccak256[""]);
  assert.equal(keccak256Hex("abc"), V.keccak256.abc);
  assert.equal(serializarJcs(V.jcs.input), V.jcs.output);
  assert.throws(() => serializarJcs({ a: Number.NaN }), TypeError);
  assert.throws(() => serializarJcs({ a: undefined }), TypeError);
});

test("SV-02 Moira key derivations match the public vectors and refuse bad input", () => {
  const m = V.moira;
  assert.equal(compromisoSalMoira(m.salt), m.commitment);
  assert.equal(claveSalMoira(m.commitment), m.saltSlot);
  assert.equal(etiquetaDuenoSalMoira(m.clientRef, m.period, m.commitment), m.ownerTag);
  assert.equal(claveBloqueoMoira(m.salt, m.material), m.lockSlot);
  assert.equal(claveRevelacionMoira(m.lockSlot, "STC", null), m.revealStc);
  assert.equal(claveRevelacionMoira(m.lockSlot, "CLIENTE", null), m.revealClient);
  assert.equal(claveRevelacionMoira(m.lockSlot, "AUDITOR", m.auditorRef), m.revealAuditor);
  assert.equal(claveIntento(m.lockSlot, "CLOSE", 1), m.closeAttempt1);
  assert.equal(canonicalizarRfc(m.rfcInput), m.rfcCanonical);
  // Every role has its own slot.
  assert.equal(new Set([m.revealStc, m.revealClient, m.revealAuditor]).size, 3);
  assert.throws(() => compromisoSalMoira("0".repeat(64)), /MOIRA_SALT_INVALID/);
  assert.throws(() => etiquetaDuenoSalMoira(m.clientRef, "2025-01", m.commitment), /MOIRA_PERIOD_INVALID/);
  assert.throws(() => claveRevelacionMoira(m.lockSlot, "AUDITOR", null), /MOIRA_AUDITOR_REF_INVALID/);
  assert.throws(() => claveRevelacionMoira(m.lockSlot, "STC", m.auditorRef), /MOIRA_AUDITOR_REF_INVALID/);
  assert.throws(() => claveIntento(m.lockSlot, "CLOSE", -1), /ATTEMPT_NUMBER_INVALID/);
  for (const bad of ["XAXX010101000ß", "XAXX011301000", "XAXX010132000", "XAX"]) {
    assert.throws(() => canonicalizarRfc(bad), /MOIRA_RFC_INVALID/, bad);
  }
});

test("SV-03 a receipt verifies only under its key, deployment and exact text", () => {
  const campos = verificarRecibo(V.receipt, V.receiptPublicKey, V.deployment);
  assert.equal(campos.operation, "MOIRA_BLOQUEO");
  assert.equal(campos.entries[0]?.key, V.moira.lockSlot);
  assert.throws(() => verificarRecibo(V.receipt, V.receiptPublicKey, "ab".repeat(32)), /STYX_RECEIPT_INVALID/);
  const other = "302a300506032b6570032100" + "11".repeat(32);
  assert.throws(() => verificarRecibo(V.receipt, other, V.deployment), /STYX_RECEIPT_INVALID/);
  const spaced = { ...V.receipt, signedText: V.receipt.signedText.replace(":", ": ") };
  assert.throws(() => verificarRecibo(spaced, V.receiptPublicKey, V.deployment), /STYX_RECEIPT_INVALID/);
  const flipped = { ...V.receipt, signature: (V.receipt.signature[0] === "a" ? "b" : "a") + V.receipt.signature.slice(1) };
  assert.throws(() => verificarRecibo(flipped, V.receiptPublicKey, V.deployment), /STYX_RECEIPT_INVALID/);
  // A statement signed by the same key is never a receipt, and the other way round.
  assert.throws(() => verificarRecibo(V.statement, V.receiptPublicKey, V.deployment), /STYX_RECEIPT_INVALID/);
  assert.throws(() => verificarDeclaracionReferencia(V.receipt, V.receiptPublicKey, V.deployment), /MOIRA_REF_STATEMENT_INVALID/);
});

test("SV-04 a client-reference statement verifies only under its key and deployment", () => {
  const ok = verificarDeclaracionReferencia(V.statement, V.receiptPublicKey, V.deployment);
  assert.equal(ok.rfc, "XAXX010101000");
  assert.equal(ok.clientRef, V.moira.clientRef);
  assert.throws(() => verificarDeclaracionReferencia(V.statement, V.receiptPublicKey, "ab".repeat(32)), /MOIRA_REF_STATEMENT_INVALID/);
  // Same signature, text with a swapped client reference.
  const swapped = { ...V.statement, signedText: V.statement.signedText.replace(V.moira.clientRef, "cd".repeat(32)) };
  assert.throws(() => verificarDeclaracionReferencia(swapped, V.receiptPublicKey, V.deployment), /MOIRA_REF_STATEMENT_INVALID/);
});

// --- read-only log reader over fake JSON-RPC chains ---------------------------

const CONTRACT = `0x${"c1".repeat(20)}`;
const WRITER = `0x${"a1".repeat(20)}`;
const NOW_MS = Date.parse("2026-11-07T12:00:00.000Z");
const word = (hex: string) => hex.padStart(64, "0");

class ChainFalsa {
  readonly entries = new Map<string, { value: string; timeS: number }>();
  blockS = NOW_MS / 1000 - 10;
  fail = false;
  readonly calls: string[] = [];
  async getBlockByNumber(tag: "finalized") {
    assert.equal(tag, "finalized");
    if (this.fail) throw new Error("down");
    return { timestamp: `0x${this.blockS.toString(16)}` };
  }
  async call(call: { to: string; data: string }, tag: "finalized") {
    assert.equal(tag, "finalized");
    this.calls.push(call.data);
    assert.equal(call.to, CONTRACT);
    assert.equal(call.data.slice(0, 10), SELECTOR_GET_ONE_ENTRY_LOG);
    assert.equal(call.data.slice(10, 74), word(WRITER.slice(2)));
    const entry = this.entries.get(`0x${call.data.slice(74)}`);
    return entry === undefined ? `0x${"0".repeat(128)}` : `0x${entry.value.slice(2)}${word(entry.timeS.toString(16))}`;
  }
}

function lector() {
  const chains = { ALERA: new ChainFalsa(), POLYGON: new ChainFalsa(), SEI: new ChainFalsa() };
  const cadenas: CadenaLecturaStyx[] = (Object.keys(chains) as CadenaTestigo[]).map((chain) => ({
    chain, rpc: chains[chain], contract: CONTRACT, writer: WRITER,
  }));
  return { chains, reader: new LectorTestigoStyx({ cadenas, ahoraMs: () => NOW_MS, maxEdadMs: 60_000 }) };
}

test("SV-05 the reader returns a value only when two fresh chains agree, with their entry times", async () => {
  const { chains, reader } = lector();
  const key = V.moira.lockSlot;
  const value = `0x${"77".repeat(32)}`;
  assert.equal(await reader.leerClave(key), null);
  chains.ALERA.entries.set(key, { value, timeS: NOW_MS / 1000 - 100 });
  // One chain alone: the other two still agree it is unwritten.
  assert.equal(await reader.leerClave(key), null);
  chains.SEI.entries.set(key, { value, timeS: NOW_MS / 1000 - 90 });
  const entry = await reader.leerClaveConTiempos(key);
  assert.equal(entry?.value, value);
  assert.deepEqual(entry?.escritoEn.map((t) => t.cadena).sort(), ["ALERA", "SEI"]);
  assert.deepEqual(entry?.escritoEn.map((t) => t.ms).sort(), [NOW_MS - 100_000, NOW_MS - 90_000]);
  // A stale chain gives no vote: SEI stalls, POLYGON says unwritten, ALERA says written: no quorum.
  chains.SEI.blockS = NOW_MS / 1000 - 3600;
  await assert.rejects(() => reader.leerClave(key), /CHAIN_WITNESS_NO_QUORUM/);
  // An entry stamped after its chain's finalized block gives no vote either.
  chains.SEI.blockS = NOW_MS / 1000 - 10;
  chains.SEI.entries.set(key, { value, timeS: NOW_MS / 1000 });
  await assert.rejects(() => reader.leerClave(key), /CHAIN_WITNESS_NO_QUORUM/);
  // Two chains down: no quorum, never a guess.
  chains.SEI.entries.set(key, { value, timeS: NOW_MS / 1000 - 90 });
  chains.POLYGON.fail = true;
  chains.SEI.fail = true;
  await assert.rejects(() => reader.leerClave(key), /CHAIN_WITNESS_NO_QUORUM/);
});

test("SV-06 the reader scans attempts in order and refuses bad config", async () => {
  const { chains, reader } = lector();
  const lockKey = V.moira.lockSlot;
  const bad = `0x${"01".repeat(32)}`;
  const good = `0x${"02".repeat(32)}`;
  for (const chain of Object.values(chains)) {
    chain.entries.set(claveIntento(lockKey, "CLOSE", 0), { value: bad, timeS: NOW_MS / 1000 - 50 });
    chain.entries.set(claveIntento(lockKey, "CLOSE", 1), { value: good, timeS: NOW_MS / 1000 - 40 });
  }
  const first = await reader.leerPrimeroValidoConTiempos(lockKey, "CLOSE", (v) => v === good);
  assert.equal(first?.n, 1);
  assert.equal(first?.escritoEn.length, 3);
  assert.equal(await reader.leerPrimeroValidoConTiempos(lockKey, "CLOSE", () => false), null);
  const base = { chain: "ALERA" as const, rpc: chains.ALERA, contract: CONTRACT, writer: WRITER };
  for (const cadenas of [
    [base, base, base],
    [base, { ...base, chain: "POLYGON" as const }],
    [base, { ...base, chain: "POLYGON" as const }, { ...base, chain: "SEI" as const, contract: "0xABC" }],
  ]) {
    assert.throws(() => new LectorTestigoStyx({ cadenas, maxEdadMs: 1 }), /READER_CONFIG_INVALID/);
  }
  await assert.rejects(() => reader.leerClave("0x12"), /CHAIN_WITNESS_KEY_INVALID/);
});

test("SV-08 review fixes: deployment is required, a hung chain gives no vote, one RPC cannot be three chains", async () => {
  assert.throws(() => verificarRecibo(V.receipt, V.receiptPublicKey, undefined as never), /STYX_RECEIPT_INVALID/);
  assert.throws(() => verificarDeclaracionReferencia(V.statement, V.receiptPublicKey, undefined as never), /MOIRA_REF_STATEMENT_INVALID/);
  const chains = { ALERA: new ChainFalsa(), POLYGON: new ChainFalsa(), SEI: new ChainFalsa() };
  const value = `0x${"55".repeat(32)}`;
  const key = V.moira.saltSlot;
  chains.ALERA.entries.set(key, { value, timeS: NOW_MS / 1000 - 100 });
  chains.POLYGON.entries.set(key, { value, timeS: NOW_MS / 1000 - 100 });
  // SEI never answers: the two others still decide, within the per-chain limit.
  chains.SEI.getBlockByNumber = () => new Promise(() => undefined);
  const cadenas: CadenaLecturaStyx[] = (Object.keys(chains) as CadenaTestigo[]).map((chain) => ({
    chain, rpc: chains[chain], contract: CONTRACT, writer: WRITER,
  }));
  const reader = new LectorTestigoStyx({ cadenas, ahoraMs: () => NOW_MS, maxEdadMs: 60_000, limiteCadenaMs: 50 });
  assert.equal(await reader.leerClave(key), value);
  // Shared RPC object, a too-large age bound, a bad limit: refused.
  const shared = cadenas.map((cadena) => ({ ...cadena, rpc: chains.ALERA }));
  assert.throws(() => new LectorTestigoStyx({ cadenas: shared, maxEdadMs: 60_000 }), /READER_CONFIG_INVALID/);
  assert.throws(() => new LectorTestigoStyx({ cadenas, maxEdadMs: 24 * 3_600_000 + 1 }), /READER_CONFIG_INVALID/);
  assert.throws(() => new LectorTestigoStyx({ cadenas, maxEdadMs: 60_000, limiteCadenaMs: 0 }), /READER_CONFIG_INVALID/);
});

test("SV-07 a lock acceptance verifies only under its key and deployment, and its domain is its own", () => {
  const ok = verificarAceptacionBloqueoMoira(V.lockAcceptance, V.receiptPublicKey, V.deployment);
  assert.equal(ok.lockId, "0123456789abcdef0123456789abcdef");
  assert.equal(ok.priorDiagnosis, false);
  assert.throws(() => verificarAceptacionBloqueoMoira(V.lockAcceptance, V.receiptPublicKey, "ab".repeat(32)), /MOIRA_LOCK_ACCEPTANCE_INVALID/);
  // Flip priorDiagnosis under the same signature.
  const flipped = { ...V.lockAcceptance, signedText: V.lockAcceptance.signedText.replace('"priorDiagnosis":false', '"priorDiagnosis":true') };
  assert.throws(() => verificarAceptacionBloqueoMoira(flipped, V.receiptPublicKey, V.deployment), /MOIRA_LOCK_ACCEPTANCE_INVALID/);
  // Receipts and statements by the same key are never acceptances, and acceptances never receipts or statements.
  assert.throws(() => verificarAceptacionBloqueoMoira(V.receipt, V.receiptPublicKey, V.deployment), /MOIRA_LOCK_ACCEPTANCE_INVALID/);
  assert.throws(() => verificarAceptacionBloqueoMoira(V.statement, V.receiptPublicKey, V.deployment), /MOIRA_LOCK_ACCEPTANCE_INVALID/);
  assert.throws(() => verificarRecibo(V.lockAcceptance, V.receiptPublicKey, V.deployment), /STYX_RECEIPT_INVALID/);
  assert.throws(() => verificarDeclaracionReferencia(V.lockAcceptance, V.receiptPublicKey, V.deployment), /MOIRA_REF_STATEMENT_INVALID/);
  // Domain separation at the signature level: the acceptance text signed under
  // another domain (or none) never verifies as an acceptance.
  const keys = generateKeyPairSync("ed25519");
  const pub = keys.publicKey.export({ format: "der", type: "spki" }).toString("hex");
  const text = textoAceptacionBloqueoMoira({
    deployment: V.deployment, lockId: "ab".repeat(16), lockRecordHash: "cd".repeat(32), priorDiagnosis: true,
    acceptedAt: "2026-11-07T12:00:00.000Z",
  });
  const sig = (bytes: Buffer) => sign(null, bytes, keys.privateKey).toString("hex");
  assert.equal(verificarAceptacionBloqueoMoira({ signedText: text, signature: sig(mensajeAceptacionBloqueoMoira(text)) }, pub, V.deployment).priorDiagnosis, true);
  for (const bytes of [Buffer.from(text), mensajeReciboFirmado(text), mensajeDeclaracionReferencia(text)]) {
    assert.throws(() => verificarAceptacionBloqueoMoira({ signedText: text, signature: sig(bytes) }, pub, V.deployment), /MOIRA_LOCK_ACCEPTANCE_INVALID/);
  }
  // Bad field shapes are refused before any signature check.
  for (const over of [{ lockId: "ab".repeat(15) }, { lockRecordHash: "AB".repeat(32) }, { priorDiagnosis: "false" }, { acceptedAt: "2026-11-07T12:00:00Z" }]) {
    const bad = JSON.stringify({ ...JSON.parse(text), ...over });
    assert.throws(() => verificarAceptacionBloqueoMoira({ signedText: bad, signature: sig(mensajeAceptacionBloqueoMoira(bad)) }, pub, V.deployment), /MOIRA_LOCK_ACCEPTANCE_INVALID/);
  }
});

test("SV-09 the deployment id binds chain ids, contracts, writer and receipt key", () => {
  const pub = "302a300506032b6570032100" + "11".repeat(32);
  const cadenas = [
    { chain: "SEI" as const, chainId: "1328", contract: `0x${"03".repeat(20)}`, writer: `0x${"0a".repeat(20)}` },
    { chain: "ALERA" as const, chainId: "100001", contract: `0x${"01".repeat(20)}`, writer: `0x${"0a".repeat(20)}` },
    { chain: "POLYGON" as const, chainId: "80002", contract: `0x${"02".repeat(20)}`, writer: `0x${"0a".repeat(20)}` },
  ];
  const id = idDespliegueStyx(cadenas, pub);
  assert.match(id, /^[0-9a-f]{64}$/u);
  // Input order does not matter; every field does.
  assert.equal(idDespliegueStyx([...cadenas].reverse(), pub), id);
  assert.notEqual(idDespliegueStyx(cadenas.map((c) => c.chain === "POLYGON" ? { ...c, chainId: "137" } : c), pub), id);
  assert.notEqual(idDespliegueStyx(cadenas.map((c) => c.chain === "SEI" ? { ...c, contract: `0x${"04".repeat(20)}` } : c), pub), id);
  assert.notEqual(idDespliegueStyx(cadenas, "302a300506032b6570032100" + "22".repeat(32)), id);
  for (const bad of [cadenas.slice(0, 2), [...cadenas.slice(0, 2), { ...cadenas[0]!, chain: "ALERA" as const }],
    cadenas.map((c) => ({ ...c, contract: c.contract.toUpperCase() })), cadenas.map((c) => ({ ...c, chainId: "1" })),
    cadenas.map((c) => ({ ...c, contract: `0x${"0".repeat(40)}` })), cadenas.map((c) => ({ ...c, contract: c.writer }))]) {
    assert.throws(() => idDespliegueStyx(bad, pub), /STYX_DEPLOYMENT_INVALID/);
  }
});

test("SV-10 a two-chain test deployment (POLYGON and SEI) gets its own id, never a three-chain one", () => {
  const pub = "302a300506032b6570032100" + "11".repeat(32);
  const polygon = { chain: "POLYGON" as const, chainId: "80002", contract: `0x${"02".repeat(20)}`, writer: `0x${"0a".repeat(20)}` };
  const sei = { chain: "SEI" as const, chainId: "1328", contract: `0x${"03".repeat(20)}`, writer: `0x${"0a".repeat(20)}` };
  const alera = { chain: "ALERA" as const, chainId: "100001", contract: `0x${"01".repeat(20)}`, writer: `0x${"0a".repeat(20)}` };
  const two = idDespliegueStyx([sei, polygon], pub);
  assert.match(two, /^[0-9a-f]{64}$/u);
  assert.equal(idDespliegueStyx([polygon, sei], pub), two);
  assert.notEqual(idDespliegueStyx([alera, polygon, sei], pub), two);
  // Two chains must be exactly POLYGON and SEI.
  assert.throws(() => idDespliegueStyx([alera, polygon], pub), /STYX_DEPLOYMENT_INVALID/);
  assert.throws(() => idDespliegueStyx([polygon, polygon], pub), /STYX_DEPLOYMENT_INVALID/);
  assert.throws(() => idDespliegueStyx([polygon], pub), /STYX_DEPLOYMENT_INVALID/);
});
