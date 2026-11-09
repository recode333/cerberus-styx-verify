// Keys and values of Hades log head seals, shared by the operator's seal
// service, the box seal-submit client and anyone who reads the chain.
//
// Key of seal n for a box: keccak256(keccak256("STYX-HADES-HEAD-V1") || boxRef || uint256 n).
// boxRef is a 32-byte hash of the box id; no name ever reaches a key.
//
// Value: reason (1 byte: 01 daily, 02 after a restore) || log sequence
// (7 bytes) || first 24 bytes of the log head sha256.

import { keccak256Hex } from "./keccak256.ts";

export type MotivoSelloHades = "DIARIO" | "RESTAURACION";

/** A Hades log head: last record sequence (from 1) and its chain hash. */
export interface CabezaLogHades {
  readonly seq: number;
  readonly sha256: string;
}

export interface SelloHadesLeido {
  readonly n: number;
  readonly motivo: MotivoSelloHades;
  readonly seq: number;
  /** First 24 bytes of the sealed head sha256, hex. */
  readonly prefijoSha256: string;
}

const PREFIJO = keccak256Hex("STYX-HADES-HEAD-V1");
const HEX32 = /^[0-9a-f]{64}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
export const SEQ_MAX_SELLO_HADES = Math.min(Number.MAX_SAFE_INTEGER, 2 ** 56 - 1);
const MOTIVO_BYTE: Readonly<Record<MotivoSelloHades, string>> = Object.freeze({ DIARIO: "01", RESTAURACION: "02" });

function word(value: bigint): string {
  return value.toString(16).padStart(64, "0");
}

export function claveSelloHades(boxRef: string, n: number): string {
  if (typeof boxRef !== "string" || !HEX32.test(boxRef)) throw new Error("HADES_SEAL_BOX_REF_INVALID");
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("HADES_SEAL_NUMBER_INVALID");
  return `0x${keccak256Hex(Buffer.from(`${PREFIJO}${boxRef}${word(BigInt(n))}`, "hex"))}`;
}

/** Throws HADES_SEAL_HEAD_INVALID unless `value` is exactly { seq, sha256 } and well formed. */
export function validarCabezaHades(value: unknown): CabezaLogHades {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("HADES_SEAL_HEAD_INVALID");
  const head = value as Record<string, unknown>;
  if (Object.keys(head).sort().join("\u0000") !== "seq\u0000sha256") throw new Error("HADES_SEAL_HEAD_INVALID");
  // Each field is read exactly once, so a getter cannot answer differently.
  const seq = head["seq"];
  const sha256 = head["sha256"];
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1 || seq > SEQ_MAX_SELLO_HADES
    || typeof sha256 !== "string" || !HEX32.test(sha256)) {
    throw new Error("HADES_SEAL_HEAD_INVALID");
  }
  return Object.freeze({ seq, sha256 });
}

export function valorSelloHades(cabeza: CabezaLogHades, motivo: MotivoSelloHades): string {
  const head = validarCabezaHades(cabeza);
  const reason = Object.hasOwn(MOTIVO_BYTE, motivo) ? MOTIVO_BYTE[motivo] : undefined;
  if (reason === undefined) throw new Error("HADES_SEAL_REASON_INVALID");
  return `0x${reason}${BigInt(head.seq).toString(16).padStart(14, "0")}${head.sha256.slice(0, 48)}`;
}

export function decodificarSelloHades(n: number, value: string): SelloHadesLeido {
  if (typeof value !== "string" || !BYTES32.test(value)) throw new Error("HADES_SEAL_VALUE_INVALID");
  const reason = value.slice(2, 4);
  const motivo: MotivoSelloHades | null = reason === "01" ? "DIARIO" : reason === "02" ? "RESTAURACION" : null;
  const seq = BigInt(`0x${value.slice(4, 18)}`);
  if (motivo === null || seq < 1n || seq > BigInt(SEQ_MAX_SELLO_HADES)) throw new Error("HADES_SEAL_VALUE_INVALID");
  return Object.freeze({ n, motivo, seq: Number(seq), prefijoSha256: value.slice(18) });
}

// Daily heads: their own numbered series, separate from restore
// heads. Key of daily seal n: keccak256(keccak256("STYX-HADES-DAILY-V1") ||
// boxRef || uint256 n). Value: the FULL 32-byte sha256 of the log head. The
// sequence number is not stored: the head is a chain hash that already
// commits to its own sequence and to every earlier record, so the box finds
// it again by looking the hash up in its log.
const PREFIJO_DIARIO = keccak256Hex("STYX-HADES-DAILY-V1");

export function claveSelloDiarioHades(boxRef: string, n: number): string {
  if (typeof boxRef !== "string" || !HEX32.test(boxRef)) throw new Error("HADES_SEAL_BOX_REF_INVALID");
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("HADES_SEAL_NUMBER_INVALID");
  return `0x${keccak256Hex(Buffer.from(`${PREFIJO_DIARIO}${boxRef}${word(BigInt(n))}`, "hex"))}`;
}

export function valorSelloDiarioHades(cabeza: CabezaLogHades): string {
  return `0x${validarCabezaHades(cabeza).sha256}`;
}

/** The full head sha256 (hex, no 0x) of a daily seal value. */
export function decodificarSelloDiarioHades(value: string): string {
  if (typeof value !== "string" || !BYTES32.test(value)) throw new Error("HADES_SEAL_VALUE_INVALID");
  return value.slice(2);
}
