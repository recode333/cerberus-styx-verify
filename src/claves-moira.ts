// Key derivations of the Moira entries on the Styx log, so anyone holding the
// salt (and, for an owner tag, the client reference) can find and check each
// entry on chain without the operator. Every key is keccak256 over fixed domain
// prefixes and 32-byte parts; nothing here needs a secret.
//
//   commitment   = keccak256(keccak256("STYX-MOIRA-SALT-COMMIT-V1") || salt)
//   salt key     = keccak256(keccak256("STYX-MOIRA-SALT-V1") || commitment)
//   owner tag    = keccak256(keccak256("STYX-MOIRA-SALT-OWNER-V1") || clientRef || keccak256(period) || commitment)
//   lock key     = keccak256(keccak256("STYX-MOIRA-LOCK-V1") || salt || material)
//   reveal slot  = keccak256(keccak256("STYX-MOIRA-REVEAL-V1") || lockKey || keccak256(role) || auditorRef or 0^32)
//   attempt key  = keccak256(abi.encode(bytes32 lockKey, keccak256(bytes(kind)), uint256 n))

import { keccak256Hex } from "./keccak256.ts";

const HEX32 = /^[0-9a-f]{64}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
/** One format only: a calendar year. */
const PERIODO = /^[0-9]{4}$/u;
const P_COMPROMISO = keccak256Hex("STYX-MOIRA-SALT-COMMIT-V1");
const P_SAL = keccak256Hex("STYX-MOIRA-SALT-V1");
const P_DUENO = keccak256Hex("STYX-MOIRA-SALT-OWNER-V1");
const P_BLOQUEO = keccak256Hex("STYX-MOIRA-LOCK-V1");
const P_REVELACION = keccak256Hex("STYX-MOIRA-REVEAL-V1");
const ZERO_HEX32 = "0".repeat(64);

function k(hexNo0x: string): string {
  return `0x${keccak256Hex(Buffer.from(hexNo0x, "hex"))}`;
}

function exigirPeriodo(periodo: unknown): string {
  if (typeof periodo !== "string" || !PERIODO.test(periodo)) throw new Error("MOIRA_PERIOD_INVALID");
  return periodo;
}

function exigirHex32(value: unknown, error: string): string {
  if (typeof value !== "string" || !HEX32.test(value) || /^0{64}$/u.test(value)) throw new Error(error);
  return value;
}


const RFC_MORAL = /^[A-ZÑ&]{3}[0-9]{6}[A-Z0-9]{3}$/u;
const RFC_FISICA = /^[A-ZÑ&]{4}[0-9]{6}[A-Z0-9]{3}$/u;

/**
 * The one canonical form of an RFC: Unicode NFC, upper case, spaces and
 * hyphens removed, 12 (moral) or 13 (física) characters with a real date.
 * Anything else is refused, so formatting can never yield a second identity.
 */
export function canonicalizarRfc(rfc: unknown): string {
  if (typeof rfc !== "string" || rfc.length > 40) throw new Error("MOIRA_RFC_INVALID");
  const nfc = rfc.normalize("NFC");
  // Whitelist BEFORE case folding: characters like ß, ſ, ı, the Kelvin sign or
  // ligatures would otherwise fold into legal RFC letters.
  if (!/^[A-Za-zÑñ&0-9 \t-]+$/u.test(nfc)) throw new Error("MOIRA_RFC_INVALID");
  const canonical = nfc.toUpperCase().replace(/[ \t-]/gu, "");
  if (!RFC_MORAL.test(canonical) && !RFC_FISICA.test(canonical)) throw new Error("MOIRA_RFC_INVALID");
  const date = canonical.slice(canonical.length - 9, canonical.length - 3);
  const year = Number(date.slice(0, 2));
  const month = Number(date.slice(2, 4));
  const day = Number(date.slice(4, 6));
  const maxDay = [31, year % 4 === 0 ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (maxDay === undefined || day < 1 || day > maxDay) throw new Error("MOIRA_RFC_INVALID");
  return canonical;
}

/** Commitment of a salt (0x, 32 bytes). */
export function compromisoSalMoira(sal: string): string {
  return k(`${P_COMPROMISO}${exigirHex32(sal, "MOIRA_SALT_INVALID")}`);
}

export function claveSalMoira(compromiso: string): string {
  if (!BYTES32.test(compromiso)) throw new Error("MOIRA_SALT_COMMITMENT_INVALID");
  return k(`${P_SAL}${compromiso.slice(2)}`);
}

export function etiquetaDuenoSalMoira(clienteRef: string, periodo: string, compromiso: string): string {
  if (!BYTES32.test(compromiso)) throw new Error("MOIRA_SALT_COMMITMENT_INVALID");
  return k(`${P_DUENO}${exigirHex32(clienteRef, "MOIRA_CLIENT_REF_INVALID")}${keccak256Hex(exigirPeriodo(periodo))}${compromiso.slice(2)}`);
}

export function claveBloqueoMoira(sal: string, material: string): string {
  return k(`${P_BLOQUEO}${exigirHex32(sal, "MOIRA_SALT_INVALID")}${exigirHex32(material, "MOIRA_LOCK_MATERIAL_INVALID")}`);
}

export type RolRevelacionMoira = "STC" | "CLIENTE" | "AUDITOR";

/** The reveal slot of one party for a lock; `auditorRef` only for AUDITOR. */
export function claveRevelacionMoira(lockKey: string, rol: RolRevelacionMoira, auditorRef: string | null): string {
  if (!BYTES32.test(lockKey) || /^0x0{64}$/u.test(lockKey)) throw new Error("MOIRA_LOCK_KEY_INVALID");
  if (rol !== "STC" && rol !== "CLIENTE" && rol !== "AUDITOR") throw new Error("MOIRA_REVEAL_ROLE_INVALID");
  if (rol === "AUDITOR") exigirHex32(auditorRef, "MOIRA_AUDITOR_REF_INVALID");
  else if (auditorRef !== null) throw new Error("MOIRA_AUDITOR_REF_INVALID");
  return k(`${P_REVELACION}${lockKey.slice(2)}${keccak256Hex(rol)}${auditorRef ?? ZERO_HEX32}`);
}

export type TipoIntento = "REVEAL" | "CLOSE";

/**
 * Key of attempt `n` of `kind` under `lockKey`:
 * keccak256(abi.encode(bytes32 lockKey, keccak256(bytes(kind)), uint256 n)).
 */
export function claveIntento(lockKey: string, kind: TipoIntento, n: number): string {
  if (!BYTES32.test(lockKey)) throw new Error("CHAIN_WITNESS_KEY_INVALID");
  if (kind !== "REVEAL" && kind !== "CLOSE") throw new Error("CHAIN_WITNESS_ATTEMPT_KIND_INVALID");
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("CHAIN_WITNESS_ATTEMPT_NUMBER_INVALID");
  return k(`${lockKey.slice(2)}${keccak256Hex(kind)}${BigInt(n).toString(16).padStart(64, "0")}`);
}
