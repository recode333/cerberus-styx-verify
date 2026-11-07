// Signed submission receipts. Every write the operator accepts for a
// party returns a receipt signed by the operator's receipt key, issued BEFORE the chain
// write. If the operator later drops the write, the party holds proof that the operator accepted
// it, so a missing reveal cannot be blamed on the party. A write that fails
// after acceptance throws with the receipt attached.
//
// Signed text: RFC 8785 canonical JSON of exactly
//   kind "STYX_SUBMISSION_RECEIPT", version 1,
//   receiptId   64 hex, random
//   deployment  64 hex: which Styx deployment (chain set and contracts) accepted it
//   operation   what was accepted (see OperacionReciboStyx)
//   submitter   { type, ref }: the verified credential subject
//   entries     [{ key, value }]: the on-chain keys and values the operator will write
//   acceptedAt  ISO 8601 UTC with milliseconds, from the chain clock
// Signature: Ed25519 over "STYX-SUBMISSION-RECEIPT-V1" || 0x00 || the UTF-8
// signed text, so the key's signatures for receipts can never be confused
// with any other use of it.
// Verification needs only the pinned public key.
//
// What a receipt proves (relying-party rule): the operator accepted that write at that
// time, after every check the operator can make before writing. The operator dropped an
// accepted write if, once the write window has passed, an entry of the
// receipt is EMPTY on chain AND every earlier entry of the same receipt holds
// exactly its value. A DIFFERENT value under an entry key is evidence against
// the operator unless the operator produces, from its durable receipt log, a receipt for that
// value issued to a submitter entitled to that key: the operator writes nothing it did
// not receipt first. The receipt also names its deployment; check it against
// the deployment you expect. `acceptedAt` is the chain clock (a median across chains); compare it
// with entry times only coarsely, never chain by chain.

import { createPublicKey, verify as cryptoVerify, type KeyObject } from "node:crypto";

import { serializarJcs } from "./jcs.ts";

/** Who a Styx write was accepted for. */
export type TipoSujetoStyx = "CLIENTE_MOIRA" | "STC_MOIRA" | "AUDITOR_MOIRA" | "CAJA_HADES";

export type OperacionReciboStyx =
  | "MOIRA_REGISTRAR_SAL"
  | "MOIRA_BLOQUEO"
  | "MOIRA_CIERRE"
  | "MOIRA_REVELACION_CLIENTE"
  | "MOIRA_REVELACION_STC"
  | "MOIRA_REVELACION_AUDITOR";

export interface EntradaReciboStyx {
  readonly key: string;
  readonly value: string;
}

export interface ReciboEnvioStyx {
  readonly signedText: string;
  /** Ed25519 signature, 64 bytes hex. */
  readonly signature: string;
}

export interface CamposReciboStyx {
  readonly receiptId: string;
  readonly deployment: string;
  readonly operation: OperacionReciboStyx;
  readonly submitter: { readonly type: TipoSujetoStyx; readonly ref: string };
  readonly entries: readonly EntradaReciboStyx[];
  readonly acceptedAt: string;
}

const KIND = "STYX_SUBMISSION_RECEIPT";
const OPERATIONS: ReadonlySet<string> = new Set([
  "MOIRA_REGISTRAR_SAL", "MOIRA_BLOQUEO", "MOIRA_CIERRE",
  "MOIRA_REVELACION_CLIENTE", "MOIRA_REVELACION_STC", "MOIRA_REVELACION_AUDITOR",
]);
const SUBJECTS: ReadonlySet<string> = new Set(["CLIENTE_MOIRA", "STC_MOIRA", "AUDITOR_MOIRA", "CAJA_HADES"]);
const HEX32 = /^[0-9a-f]{64}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const SIG = /^[0-9a-f]{128}$/u;
const ISO_MS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const ED25519_SPKI = /^302a300506032b6570032100[0-9a-f]{64}$/u;
const MAX_TEXT = 4096;
const DOMINIO = Buffer.from("STYX-SUBMISSION-RECEIPT-V1\u0000", "utf8");

/** The bytes the operator's receipt key signs: the domain prefix, then the signed text. */
export function mensajeReciboFirmado(signedText: string): Buffer {
  return Buffer.concat([DOMINIO, Buffer.from(signedText, "utf8")]);
}

function invalido(): never {
  throw new Error("STYX_RECEIPT_INVALID");
}

export function textoRecibo(campos: CamposReciboStyx): string {
  return serializarJcs({
    kind: KIND,
    version: 1,
    receiptId: campos.receiptId,
    deployment: campos.deployment,
    operation: campos.operation,
    submitter: { type: campos.submitter.type, ref: campos.submitter.ref },
    entries: campos.entries.map((entry) => ({ key: entry.key, value: entry.value })),
    acceptedAt: campos.acceptedAt,
  });
}

/** Throws STYX_RECEIPT_INVALID unless every field is well formed. */
export function validarCamposRecibo(campos: CamposReciboStyx): void {
  if (typeof campos.receiptId !== "string" || !HEX32.test(campos.receiptId)
    || typeof campos.deployment !== "string" || !HEX32.test(campos.deployment)
    || /^0{64}$/u.test(campos.deployment)
    || !OPERATIONS.has(campos.operation)
    || campos.submitter === null || typeof campos.submitter !== "object"
    || !SUBJECTS.has(campos.submitter.type) || typeof campos.submitter.ref !== "string" || !HEX32.test(campos.submitter.ref)
    || !Array.isArray(campos.entries) || campos.entries.length < 1 || campos.entries.length > 4
    || campos.entries.some((entry) => entry === null || typeof entry !== "object"
      || Object.keys(entry).sort().join(",") !== "key,value"
      || typeof entry.key !== "string" || !BYTES32.test(entry.key)
      || typeof entry.value !== "string" || !BYTES32.test(entry.value))
    || typeof campos.acceptedAt !== "string" || !ISO_MS.test(campos.acceptedAt)) {
    invalido();
  }
  const ms = Date.parse(campos.acceptedAt);
  if (!Number.isSafeInteger(ms) || new Date(ms).toISOString() !== campos.acceptedAt) invalido();
}

/**
 * Checks a receipt against the operator's pinned receipt public key and returns its
 * fields. Throws STYX_RECEIPT_INVALID for anything else: wrong key, bad or
 * non-canonical text, bad signature. Keys inside a receipt are never trusted.
 */
export function verificarRecibo(
  recibo: ReciboEnvioStyx,
  clavePublica: string,
  despliegueEsperado: string,
): CamposReciboStyx {
  if (recibo === null || typeof recibo !== "object") invalido();
  const { signedText, signature } = recibo;
  if (typeof signedText !== "string" || signedText.length === 0 || signedText.length > MAX_TEXT
    || typeof signature !== "string" || !SIG.test(signature)
    || typeof clavePublica !== "string" || !ED25519_SPKI.test(clavePublica)
    || typeof despliegueEsperado !== "string" || !HEX32.test(despliegueEsperado)) {
    invalido();
  }
  let key: KeyObject;
  try {
    key = createPublicKey({ key: Buffer.from(clavePublica, "hex"), format: "der", type: "spki" });
  } catch {
    invalido();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(signedText);
  } catch {
    invalido();
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) invalido();
  const record = parsed as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== "acceptedAt,deployment,entries,kind,operation,receiptId,submitter,version"
    || record["kind"] !== KIND || record["version"] !== 1) {
    invalido();
  }
  const campos = {
    receiptId: record["receiptId"],
    deployment: record["deployment"],
    operation: record["operation"],
    submitter: record["submitter"],
    entries: record["entries"],
    acceptedAt: record["acceptedAt"],
  } as CamposReciboStyx;
  if (campos.submitter !== null && typeof campos.submitter === "object"
    && Object.keys(campos.submitter).sort().join(",") !== "ref,type") {
    invalido();
  }
  validarCamposRecibo(campos);
  if (textoRecibo(campos) !== signedText) invalido();
  let ok = false;
  try {
    ok = cryptoVerify(null, mensajeReciboFirmado(signedText), key, Buffer.from(signature, "hex"));
  } catch {
    ok = false;
  }
  if (!ok) invalido();
  if (campos.deployment !== despliegueEsperado) invalido();
  return campos;
}
