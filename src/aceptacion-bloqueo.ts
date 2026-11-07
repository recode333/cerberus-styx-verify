// Moira lock acceptance: the operator's signed statement that it checked a lock record
// before the client logs it (Moira fair-draw specification). Styx sees only
// the lock hash, so a lock counts in a report or a no-draw only with a valid
// acceptance. The checks themselves are Moira's; this file only defines the
// signed text and checks the signature.
//
// Signed text: RFC 8785 canonical JSON of exactly
//   kind           "MOIRA_LOCK_ACCEPTANCE"
//   version        1
//   deployment     64 hex: the Styx deployment, as in submission receipts
//   lockId         32 hex (16 bytes): the lock record's lockId
//   lockRecordHash 64 hex: the lock record hash
//   priorDiagnosis boolean: the operator's index answer when it accepted
//   acceptedAt     ISO 8601 UTC with milliseconds, from the chain clock;
//                  informational only, never used to refuse
// Signature: Ed25519 with the operator's receipt key over
// "MOIRA-LOCK-ACCEPTANCE-V1" || 0x00 || the UTF-8 signed text. The domain is
// its own, so an acceptance can never be read as a submission receipt or a
// client-reference statement, and none of those as an acceptance.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";

import { serializarJcs } from "./jcs.ts";

export interface AceptacionBloqueoMoira {
  readonly signedText: string;
  /** Ed25519 signature, 64 bytes hex. */
  readonly signature: string;
}

export interface CamposAceptacionBloqueoMoira {
  readonly deployment: string;
  readonly lockId: string;
  readonly lockRecordHash: string;
  readonly priorDiagnosis: boolean;
  readonly acceptedAt: string;
}

const KIND = "MOIRA_LOCK_ACCEPTANCE";
const FIELDS = "acceptedAt,deployment,kind,lockId,lockRecordHash,priorDiagnosis,version";
const HEX16 = /^[0-9a-f]{32}$/u;
const HEX32 = /^[0-9a-f]{64}$/u;
const SIG = /^[0-9a-f]{128}$/u;
const ISO_MS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const ED25519_SPKI = /^302a300506032b6570032100[0-9a-f]{64}$/u;
const MAX_TEXT = 1024;
const DOMINIO = Buffer.from("MOIRA-LOCK-ACCEPTANCE-V1\u0000", "utf8");

function invalida(): never {
  throw new Error("MOIRA_LOCK_ACCEPTANCE_INVALID");
}

/** Throws MOIRA_LOCK_ACCEPTANCE_INVALID unless every field is well formed. */
export function validarCamposAceptacionBloqueoMoira(campos: CamposAceptacionBloqueoMoira): void {
  if (campos === null || typeof campos !== "object"
    || typeof campos.deployment !== "string" || !HEX32.test(campos.deployment) || /^0{64}$/u.test(campos.deployment)
    || typeof campos.lockId !== "string" || !HEX16.test(campos.lockId)
    || typeof campos.lockRecordHash !== "string" || !HEX32.test(campos.lockRecordHash)
    || typeof campos.priorDiagnosis !== "boolean"
    || typeof campos.acceptedAt !== "string" || !ISO_MS.test(campos.acceptedAt)) {
    invalida();
  }
  const ms = Date.parse(campos.acceptedAt);
  if (!Number.isSafeInteger(ms) || new Date(ms).toISOString() !== campos.acceptedAt) invalida();
}

/** The exact text the operator signs for an acceptance. */
export function textoAceptacionBloqueoMoira(campos: CamposAceptacionBloqueoMoira): string {
  return serializarJcs({
    kind: KIND,
    version: 1,
    deployment: campos.deployment,
    lockId: campos.lockId,
    lockRecordHash: campos.lockRecordHash,
    priorDiagnosis: campos.priorDiagnosis,
    acceptedAt: campos.acceptedAt,
  });
}

/** The bytes the operator's receipt key signs for an acceptance: the domain prefix, then the text. */
export function mensajeAceptacionBloqueoMoira(signedText: string): Buffer {
  return Buffer.concat([DOMINIO, Buffer.from(signedText, "utf8")]);
}

/**
 * Checks an acceptance against the operator's pinned receipt public key and returns
 * its fields. Throws MOIRA_LOCK_ACCEPTANCE_INVALID for anything else: wrong
 * key, bad or non-canonical text, bad signature, or another deployment than
 * `despliegueEsperado` (required). The caller then compares lockId, lockRecordHash and
 * priorDiagnosis with its own lock record.
 */
export function verificarAceptacionBloqueoMoira(
  aceptacion: AceptacionBloqueoMoira,
  clavePublica: string,
  despliegueEsperado: string,
): CamposAceptacionBloqueoMoira {
  if (aceptacion === null || typeof aceptacion !== "object" || Array.isArray(aceptacion)) invalida();
  let signedText: unknown;
  let signature: unknown;
  try {
    // Each field read once, so a getter cannot answer twice.
    ({ signedText, signature } = aceptacion as unknown as Record<string, unknown>);
  } catch {
    invalida();
  }
  if (typeof signedText !== "string" || signedText.length === 0 || signedText.length > MAX_TEXT
    || typeof signature !== "string" || !SIG.test(signature)
    || typeof clavePublica !== "string" || !ED25519_SPKI.test(clavePublica)
    || typeof despliegueEsperado !== "string" || !HEX32.test(despliegueEsperado)) {
    invalida();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(signedText);
  } catch {
    invalida();
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) invalida();
  const record = parsed as Record<string, unknown>;
  if (Object.keys(record).sort().join(",") !== FIELDS || record["kind"] !== KIND || record["version"] !== 1) invalida();
  const campos = {
    deployment: record["deployment"],
    lockId: record["lockId"],
    lockRecordHash: record["lockRecordHash"],
    priorDiagnosis: record["priorDiagnosis"],
    acceptedAt: record["acceptedAt"],
  } as CamposAceptacionBloqueoMoira;
  validarCamposAceptacionBloqueoMoira(campos);
  if (textoAceptacionBloqueoMoira(campos) !== signedText) invalida();
  let ok = false;
  try {
    const key = createPublicKey({ key: Buffer.from(clavePublica, "hex"), format: "der", type: "spki" });
    ok = cryptoVerify(null, mensajeAceptacionBloqueoMoira(signedText), key, Buffer.from(signature, "hex"));
  } catch {
    ok = false;
  }
  if (!ok) invalida();
  if (campos.deployment !== despliegueEsperado) invalida();
  return Object.freeze({ ...campos });
}
