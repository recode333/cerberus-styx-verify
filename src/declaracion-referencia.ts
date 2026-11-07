// The operator's signed statement linking a client reference to the client's RFC.
// A verifier who holds the statement and the operator's pinned receipt public key
// learns which reference belongs to which RFC, and can then check the salt
// owner tag on chain (see claves-moira.ts). The reference itself is an HMAC
// under a key that stays at the operator, so it cannot be computed from the RFC alone.
//
// Signed text: RFC 8785 canonical JSON of exactly
//   kind "STYX_CLIENT_REF_STATEMENT", version 1,
//   rfc        the canonical RFC (see canonicalizarRfc)
//   clientRef  64 hex
//   deployment 64 hex: the Styx deployment
//   issuedAt   ISO 8601 UTC with milliseconds
// Signature: Ed25519 over "STYX-CLIENT-REF-STATEMENT-V1" || 0x00 || the text.

import { createPublicKey, verify as cryptoVerify } from "node:crypto";

import { canonicalizarRfc } from "./claves-moira.ts";
import { serializarJcs } from "./jcs.ts";

/** A statement signed by the operator linking a client reference to its RFC. */
export interface DeclaracionReferenciaCliente {
  readonly signedText: string;
  readonly signature: string;
}

const HEX32 = /^[0-9a-f]{64}$/u;
const DECLARACION_KIND = "STYX_CLIENT_REF_STATEMENT";
const ISO_MS = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;

const DOMINIO_DECLARACION = Buffer.from("STYX-CLIENT-REF-STATEMENT-V1\u0000", "utf8");

/** The bytes the operator's receipt key signs for a statement: the domain prefix, then the text. */
export function mensajeDeclaracionReferencia(signedText: string): Buffer {
  return Buffer.concat([DOMINIO_DECLARACION, Buffer.from(signedText, "utf8")]);
}

/** The exact text of a statement. */
export function textoDeclaracionReferencia(campos: { rfc: string; clientRef: string; deployment: string; issuedAt: string }): string {
  return serializarJcs({
    kind: DECLARACION_KIND, version: 1, rfc: campos.rfc, clientRef: campos.clientRef,
    deployment: campos.deployment, issuedAt: campos.issuedAt,
  });
}

/**
 * Checks a client-reference statement against the operator's pinned receipt
 * public key and returns the RFC and reference it links. Throws
 * MOIRA_REF_STATEMENT_INVALID for anything else.
 */
export function verificarDeclaracionReferencia(
  declaracion: DeclaracionReferenciaCliente,
  clavePublica: string,
  despliegueEsperado: string,
): { readonly rfc: string; readonly clientRef: string; readonly deployment: string; readonly issuedAt: string } {
  const bad = (): never => { throw new Error("MOIRA_REF_STATEMENT_INVALID"); };
  if (declaracion === null || typeof declaracion !== "object") bad();
  const { signedText, signature } = declaracion;
  if (typeof signedText !== "string" || signedText.length > 1024 || typeof signature !== "string"
    || !/^[0-9a-f]{128}$/u.test(signature) || typeof clavePublica !== "string"
    || !/^302a300506032b6570032100[0-9a-f]{64}$/u.test(clavePublica)) {
    bad();
  }
  let parsed: Record<string, unknown> = {};
  try {
    const value: unknown = JSON.parse(signedText);
    if (value === null || typeof value !== "object" || Array.isArray(value)) bad();
    parsed = value as Record<string, unknown>;
  } catch {
    bad();
  }
  const { rfc, clientRef, deployment, issuedAt } = parsed;
  if (Object.keys(parsed).sort().join(",") !== "clientRef,deployment,issuedAt,kind,rfc,version"
    || parsed["kind"] !== DECLARACION_KIND || parsed["version"] !== 1
    || typeof rfc !== "string" || typeof clientRef !== "string" || !HEX32.test(clientRef)
    || typeof deployment !== "string" || !HEX32.test(deployment) || /^0{64}$/u.test(deployment)
    || typeof despliegueEsperado !== "string" || deployment !== despliegueEsperado
    || typeof issuedAt !== "string" || !ISO_MS.test(issuedAt) || !Number.isSafeInteger(Date.parse(issuedAt))
    || new Date(Date.parse(issuedAt)).toISOString() !== issuedAt) {
    bad();
  }
  try {
    if (canonicalizarRfc(rfc) !== rfc) bad();
  } catch {
    bad();
  }
  const fields = { rfc: rfc as string, clientRef: clientRef as string, deployment: deployment as string, issuedAt: issuedAt as string };
  if (textoDeclaracionReferencia(fields) !== signedText) bad();
  let ok = false;
  try {
    const key = createPublicKey({ key: Buffer.from(clavePublica, "hex"), format: "der", type: "spki" });
    ok = cryptoVerify(null, mensajeDeclaracionReferencia(signedText), key, Buffer.from(signature, "hex"));
  } catch {
    ok = false;
  }
  if (!ok) bad();
  return Object.freeze(fields);
}
