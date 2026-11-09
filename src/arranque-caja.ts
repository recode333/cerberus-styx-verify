// The box start check: a Hades box compares its local
// evidence log against EVERY past seal of its own, read straight from the
// chains, so nobody (the operator included) can hide a missing or changed seal.
// One implementation: the operator's seal registries run the same functions.
//
// A pass is a self-check run by the box against public chain data. It
// catches a box whose own log was damaged or rewritten; it is never
// attestation to anyone else, because anyone who reads the chain can build
// answers that pass.

import {
  claveSelloDiarioHades,
  claveSelloHades,
  decodificarSelloDiarioHades,
  decodificarSelloHades,
  validarCabezaHades,
  type CabezaLogHades,
  type SelloHadesLeido,
} from "./sello-hades.ts";
import { etiquetaModoTestigo, type ModoTestigo } from "./lector-testigo.ts";

/** Reads one key: the finalized value both (or 2 of 3) chains agree on, or null. */
export type LeerClaveStyx = (key: string) => Promise<string | null>;

/** What the box shows of its local evidence log. */
export interface LogArranqueCaja {
  /** The local head, or null for an empty log. */
  cabeza(): Promise<CabezaLogHades | null>;
  /** The chain hash after record `seq` (from 1), or null when there is no such record. */
  shaEn(seq: number): Promise<string | null>;
  /** The sequence (from 1) of the record whose chain hash is `sha256`, or null. */
  seqDeSha(sha256: string): Promise<number | null>;
}

export interface SelloDiarioLeido {
  readonly n: number;
  /** The full sealed head sha256, hex. */
  readonly sha256: string;
}

const HEX32 = /^[0-9a-f]{64}$/u;
const MAX_SELLOS = 2 ** 40;

/**
 * The highest written number of a gapless series, by exponential then binary
 * search; null when empty. Seals are written without gaps, so a skipped
 * number hides every later seal from this search.
 */
async function ultimoNumero(leer: (n: number) => Promise<string | null>): Promise<{ n: number; value: string } | null> {
  const first = await leer(0);
  if (first === null) return null;
  let low = 0;
  let lowValue = first;
  let high = 1;
  for (;;) {
    if (high > MAX_SELLOS) throw new Error("HADES_SEAL_SCAN_LIMIT_REACHED");
    const value = await leer(high);
    if (value === null) break;
    low = high;
    lowValue = value;
    high *= 2;
  }
  while (high - low > 1) {
    const middle = low + Math.floor((high - low) / 2);
    const value = await leer(middle);
    if (value === null) {
      high = middle;
    } else {
      low = middle;
      lowValue = value;
    }
  }
  return { n: low, value: lowValue };
}

function exigirBox(boxRef: unknown): string {
  if (typeof boxRef !== "string" || !HEX32.test(boxRef)) throw new Error("HADES_SEAL_BOX_REF_INVALID");
  return boxRef;
}

function exigirLeer(leer: unknown): LeerClaveStyx {
  if (typeof leer !== "function") throw new Error("HADES_SEAL_READER_REQUIRED");
  return leer as LeerClaveStyx;
}

/** The newest restore-series seal of a box, or null. */
export async function ultimoSelloRestauracion(leer: LeerClaveStyx, boxRef: string): Promise<SelloHadesLeido | null> {
  const box = exigirBox(boxRef);
  const r = await ultimoNumero((n) => exigirLeer(leer)(claveSelloHades(box, n)));
  return r === null ? null : decodificarSelloHades(r.n, r.value);
}

/** The newest daily-series seal of a box, or null. */
export async function ultimoSelloDiario(leer: LeerClaveStyx, boxRef: string): Promise<SelloDiarioLeido | null> {
  const box = exigirBox(boxRef);
  const r = await ultimoNumero((n) => exigirLeer(leer)(claveSelloDiarioHades(box, n)));
  return r === null ? null : Object.freeze({ n: r.n, sha256: decodificarSelloDiarioHades(r.value) });
}

/**
 * Restore series: the local log is checked against every seal, oldest first.
 * A log shorter than any seal: HADES_LOG_SHORTENED. A record at a sealed
 * sequence with another hash, or a head disagreeing with its own record:
 * HADES_LOG_REWRITTEN. A missing earlier seal: HADES_SEAL_GAP. Seals going
 * back in sequence: HADES_SEAL_VALUE_INVALID. Never sealed: null.
 */
export async function comprobarSellosRestauracion(
  leer: LeerClaveStyx,
  boxRef: string,
  log: Pick<LogArranqueCaja, "cabeza" | "shaEn">,
): Promise<SelloHadesLeido | null> {
  if (log === null || typeof log !== "object" || typeof log.cabeza !== "function" || typeof log.shaEn !== "function") {
    throw new Error("HADES_SEAL_LOG_REQUIRED");
  }
  const box = exigirBox(boxRef);
  const lee = exigirLeer(leer);
  const newest = await ultimoSelloRestauracion(lee, box);
  if (newest === null) return null;
  const rawHead = await log.cabeza();
  if (rawHead === null) throw new Error("HADES_LOG_SHORTENED");
  const local = validarCabezaHades(rawHead);
  if (local.seq < newest.seq) throw new Error("HADES_LOG_SHORTENED");
  const own = await log.shaEn(local.seq);
  if (own !== local.sha256) throw new Error("HADES_LOG_REWRITTEN");
  let previousSeq = 0;
  for (let n = 0; n <= newest.n; n += 1) {
    const value = n === newest.n ? null : await lee(claveSelloHades(box, n));
    if (n !== newest.n && value === null) throw new Error("HADES_SEAL_GAP");
    const seal = value === null ? newest : decodificarSelloHades(n, value);
    if (seal.seq < previousSeq) throw new Error("HADES_SEAL_VALUE_INVALID");
    previousSeq = seal.seq;
    const sha = await log.shaEn(seal.seq);
    if (sha === null) throw new Error("HADES_LOG_SHORTENED");
    if (typeof sha !== "string" || !HEX32.test(sha) || sha.slice(0, 48) !== seal.prefijoSha256) {
      throw new Error("HADES_LOG_REWRITTEN");
    }
  }
  return newest;
}

/**
 * Daily series: every sealed hash must be a record of the local log (else
 * HADES_LOG_REWRITTEN: shortened or rewritten), at a sequence that never goes
 * back from one seal to the next (else HADES_SEAL_VALUE_INVALID), and not
 * past the local head. A missing earlier seal: HADES_SEAL_GAP. Never sealed: null.
 */
export async function comprobarSellosDiarios(
  leer: LeerClaveStyx,
  boxRef: string,
  log: Pick<LogArranqueCaja, "cabeza" | "seqDeSha">,
): Promise<SelloDiarioLeido | null> {
  if (log === null || typeof log !== "object" || typeof log.cabeza !== "function" || typeof log.seqDeSha !== "function") {
    throw new Error("HADES_SEAL_LOG_REQUIRED");
  }
  const box = exigirBox(boxRef);
  const lee = exigirLeer(leer);
  const newest = await ultimoSelloDiario(lee, box);
  if (newest === null) return null;
  const rawHead = await log.cabeza();
  if (rawHead === null) throw new Error("HADES_LOG_REWRITTEN");
  const local = validarCabezaHades(rawHead);
  let previousSeq = 0;
  for (let n = 0; n <= newest.n; n += 1) {
    let sha: string;
    if (n === newest.n) {
      sha = newest.sha256;
    } else {
      const value = await lee(claveSelloDiarioHades(box, n));
      if (value === null) throw new Error("HADES_SEAL_GAP");
      sha = decodificarSelloDiarioHades(value);
    }
    const seq = await log.seqDeSha(sha);
    if (seq === null) throw new Error("HADES_LOG_REWRITTEN");
    if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1 || seq > local.seq) throw new Error("HADES_LOG_REWRITTEN");
    if (seq < previousSeq) throw new Error("HADES_SEAL_VALUE_INVALID");
    previousSeq = seq;
  }
  return newest;
}

export interface ResultadoArranqueCaja {
  /** The quorum the reads ran under; every report built on this prints `etiquetaModo`. */
  readonly modo: ModoTestigo;
  readonly etiquetaModo: string;
  readonly restauracion: SelloHadesLeido | null;
  readonly diario: SelloDiarioLeido | null;
}

/** The part of LectorTestigoStyx the start check uses. */
export interface LectorArranqueCaja {
  readonly modo: ModoTestigo;
  leerClave(key: string): Promise<string | null>;
}

/**
 * The box start check: both seal series of `boxRef` against the local log,
 * read through `lector` (a LectorTestigoStyx over the box's own read-only
 * RPC clients). Any error (a failed or disagreeing read, a timeout, a
 * changed log) throws, and the box stays closed for restores and sealing.
 */
export async function verificarArranqueCaja(
  lector: LectorArranqueCaja,
  boxRef: string,
  log: LogArranqueCaja,
): Promise<ResultadoArranqueCaja> {
  if (lector === null || typeof lector !== "object" || typeof lector.leerClave !== "function") {
    throw new Error("HADES_SEAL_READER_REQUIRED");
  }
  const modo = lector.modo;
  if (modo !== "2_OF_3" && modo !== "TEST_2_OF_2") throw new Error("HADES_SEAL_READER_REQUIRED");
  const leer: LeerClaveStyx = (key) => lector.leerClave(key);
  const restauracion = await comprobarSellosRestauracion(leer, boxRef, log);
  const diario = await comprobarSellosDiarios(leer, boxRef, log);
  return Object.freeze({ modo, etiquetaModo: etiquetaModoTestigo(modo), restauracion, diario });
}
