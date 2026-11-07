// Read-only client of the Styx log: the OneEntryLog contract on three chains
// (ALERA, Polygon, Sei), read at each chain's finalized block. A value counts
// only when at least two fresh chains agree on it; with it come the block
// times the contract stored on each agreeing chain. It holds no key and
// cannot write.
//
// Reading rules (the same code the log writer uses for its own reads):
// - a chain whose finalized block is older than `maxEdadMs`, or stamped more
//   than 5 minutes ahead of the local clock, gives no vote;
// - an unwritten key must have time 0; a written one a time above 0 and not
//   after that chain's finalized block; anything else gives no vote;
// - fewer than two agreeing chains: CHAIN_WITNESS_NO_QUORUM, never a guess.
// Times: compare "written before" against the latest agreeing chain time and
// "written after" against the earliest; compare two entries chain by chain,
// never across chains.

import { claveIntento, type TipoIntento } from "./claves-moira.ts";
import { exigirDespliegueModoPrueba, type DespliegueStyxPublicado } from "./despliegue.ts";
import { keccak256Hex } from "./keccak256.ts";

export type CadenaTestigo = "ALERA" | "POLYGON" | "SEI";

/**
 * The quorum a read was made under. "2_OF_3": two of ALERA, POLYGON and SEI
 * agree. "TEST_2_OF_2": test mode with POLYGON and SEI only, both must agree;
 * every report built on it must say "2 of 2, test mode".
 */
export type ModoTestigo = "2_OF_3" | "TEST_2_OF_2";

/** The words every read and report in two-chain test mode must carry. */
export const ETIQUETA_MODO_PRUEBA = "2 of 2, test mode";

export function etiquetaModoTestigo(modo: ModoTestigo): string {
  return modo === "TEST_2_OF_2" ? ETIQUETA_MODO_PRUEBA : "2 of 3";
}

export interface EntradaConTiempos {
  readonly value: string;
  readonly escritoEn: readonly { readonly cadena: CadenaTestigo; readonly ms: number }[];
  /** Under which quorum this value was read. */
  readonly modo: ModoTestigo;
}

/** The two JSON-RPC reads the client needs; any EVM JSON-RPC client can provide them. */
export interface RpcLecturaStyx {
  getBlockByNumber(tag: "finalized"): Promise<{ readonly timestamp: unknown } | null>;
  call(call: { readonly to: string; readonly data: string }, tag: "finalized"): Promise<string>;
}

export interface CadenaLecturaStyx {
  readonly chain: CadenaTestigo;
  readonly rpc: RpcLecturaStyx;
  /** OneEntryLog address, lowercase 0x hex. */
  readonly contract: string;
  /** The operator's writer address, lowercase 0x hex: only its entries are read. */
  readonly writer: string;
}

/**
 * A finalized block stamped more than this ahead of the local clock is
 * unreadable: it gives no vote.
 */
export const CHAIN_WITNESS_MAX_ADELANTO_MS = 5 * 60 * 1000;
const QUORUM = 2;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const BYTES32 = /^0x[0-9a-f]{64}$/u;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const ZERO32 = `0x${"0".repeat(64)}`;
const UINT64_MAX = (1n << 64n) - 1n;
const CHAINS: ReadonlySet<string> = new Set(["ALERA", "POLYGON", "SEI"]);
/** Selector of OneEntryLog `get(address,bytes32)`, which returns (bytes32 value, uint64 time). */
export const SELECTOR_GET_ONE_ENTRY_LOG = `0x${keccak256Hex("get(address,bytes32)").slice(0, 8)}`;

function resultadoInvalido(): never {
  throw new Error("CHAIN_WITNESS_RPC_RESULT_INVALID");
}

/** A 32-byte ABI word of a hex string (no 0x), left-padded. */
export function palabraAbi(hexNo0x: string): string {
  return hexNo0x.padStart(64, "0");
}

/** The first `count` 32-byte words of an eth_call result. */
export function decodificarPalabras(result: string, count: number): string[] {
  if (typeof result !== "string" || !/^0x(?:[0-9a-f]{64})+$/u.test(result)
    || result.length < 2 + count * 64) {
    resultadoInvalido();
  }
  const words: string[] = [];
  for (let index = 0; index < count; index += 1) {
    words.push(result.slice(2 + index * 64, 2 + (index + 1) * 64));
  }
  return words;
}

/** A JSON-RPC quantity (0x hex, no leading zeros) as a bigint. */
export function cantidadRpc(value: unknown): bigint {
  if (typeof value !== "string" || !QUANTITY.test(value)) resultadoInvalido();
  return BigInt(value);
}

/**
 * The finalized block timestamp in seconds, or null when the chain is
 * stalled (older than `maxEdadMs`) or stamped more than
 * CHAIN_WITNESS_MAX_ADELANTO_MS ahead of `ahoraMs`.
 */
export async function bloqueFinalizadoFresco(
  rpc: RpcLecturaStyx,
  ahoraMs: number,
  maxEdadMs: number,
): Promise<bigint | null> {
  const block = await rpc.getBlockByNumber("finalized");
  if (block === null || typeof block !== "object") return null;
  const timestampS = cantidadRpc(block.timestamp);
  const ageMs = ahoraMs - Number(timestampS) * 1000;
  if (!Number.isFinite(ageMs) || ageMs > maxEdadMs || ageMs < -CHAIN_WITNESS_MAX_ADELANTO_MS) return null;
  return timestampS;
}

/**
 * Value and stored entry time of `key` on one chain at its finalized block.
 * An unwritten key must have time 0; a written one a time above 0 and not
 * after `maxTimestampS` (the finalized block read just before).
 */
export async function leerEntradaEnCadena(
  cadena: Pick<CadenaLecturaStyx, "rpc" | "contract" | "writer">,
  key: string,
  maxTimestampS: bigint,
): Promise<{ readonly value: string | null; readonly timestampS: bigint }> {
  const [valueWord, timeWord] = decodificarPalabras(await cadena.rpc.call({
    to: cadena.contract,
    data: `${SELECTOR_GET_ONE_ENTRY_LOG}${palabraAbi(cadena.writer.slice(2))}${key.slice(2)}`,
  }, "finalized"), 2);
  const value = `0x${valueWord}`;
  const timestampS = BigInt(`0x${timeWord}`);
  if (value === ZERO32) {
    if (timestampS !== 0n) resultadoInvalido();
    return { value: null, timestampS };
  }
  if (timestampS === 0n || timestampS > UINT64_MAX || timestampS > maxTimestampS) resultadoInvalido();
  return { value, timestampS };
}

/**
 * The finalized value at least two fresh chains agree on for `key` (null =
 * agreed unwritten), with each agreeing chain's entry time. A chain that
 * fails, is stale or answers impossibly gives no vote. No quorum throws
 * CHAIN_WITNESS_NO_QUORUM.
 */
export async function leerEntradaQuorum(
  cadenas: readonly Pick<CadenaLecturaStyx, "chain" | "rpc" | "contract" | "writer">[],
  key: string,
  ahoraMs: number,
  maxEdadMs: number,
  limiteCadenaMs?: number,
): Promise<EntradaConTiempos | null> {
  const answers = await Promise.all(cadenas.map(async (cadena) => {
    const read = async () => {
      const fresh = await bloqueFinalizadoFresco(cadena.rpc, ahoraMs, maxEdadMs);
      if (fresh === null) return undefined;
      return { cadena: cadena.chain, ...(await leerEntradaEnCadena(cadena, key, fresh)) };
    };
    try {
      return limiteCadenaMs === undefined ? await read() : await conLimite(read(), limiteCadenaMs);
    } catch {
      return undefined;
    }
  }));
  // Three chains: two must agree. Two chains (test mode): both must agree.
  if (cadenas.length !== 3 && cadenas.length !== 2) throw new Error("CHAIN_WITNESS_CONFIG_INVALID");
  const modo: ModoTestigo = cadenas.length === 3 ? "2_OF_3" : "TEST_2_OF_2";
  const groups = new Map<string, { readonly cadena: CadenaTestigo; readonly timestampS: bigint }[]>();
  for (const answer of answers) {
    if (answer === undefined) continue;
    const id = answer.value ?? "-";
    groups.set(id, [...(groups.get(id) ?? []), { cadena: answer.cadena, timestampS: answer.timestampS }]);
  }
  for (const [id, members] of groups) {
    if (members.length < QUORUM) continue;
    if (id === "-") return null;
    const tiempos = members.map((member) => {
      const ms = Number(member.timestampS) * 1000;
      if (!Number.isSafeInteger(ms)) resultadoInvalido();
      return Object.freeze({ cadena: member.cadena, ms });
    });
    return Object.freeze({ value: id, escritoEn: Object.freeze(tiempos), modo });
  }
  throw new Error("CHAIN_WITNESS_NO_QUORUM");
}

/** Rejects when `work` takes longer than `ms`: a chain that hangs gives no vote. */
async function conLimite<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("CHAIN_WITNESS_CHAIN_TIMEOUT")), ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

const MAX_EDAD_TOPE_MS = 24 * 60 * 60 * 1000;

export interface LectorTestigoStyxConfig {
  /**
   * Exactly the three chains ALERA, POLYGON and SEI, each once; or, in
   * two-chain test mode, exactly POLYGON and SEI together with
   * `despliegueFijado` and `idDespliegueEsperado`.
   */
  readonly cadenas: readonly CadenaLecturaStyx[];
  /** Test mode only: the pinned deployment record; it must say TEST_2_OF_2. */
  readonly despliegueFijado?: DespliegueStyxPublicado;
  /** Test mode only: the deployment id the caller pins as a constant. */
  readonly idDespliegueEsperado?: string;
  /** Local clock in ms. Default Date.now. */
  readonly ahoraMs?: () => number;
  /** Oldest finalized block that still votes, in ms; at most 24 hours. */
  readonly maxEdadMs: number;
  /** Longest wait for one chain's answer before it counts as no vote. Default 10 s, at most 120 s. */
  readonly limiteCadenaMs?: number;
  /** Most attempts scanned by leerPrimeroValidoConTiempos. Default 64. */
  readonly maxIntentosLectura?: number;
}

/** Read-only, quorum-checked reads of the Styx log. */
export class LectorTestigoStyx {
  readonly #cadenas: readonly CadenaLecturaStyx[];
  readonly #ahora: () => number;
  readonly #maxEdad: number;
  readonly #maxIntentos: number;
  readonly #limiteCadena: number;
  readonly #modo: ModoTestigo;

  public constructor(config: LectorTestigoStyxConfig) {
    const invalid = (): never => { throw new Error("CHAIN_WITNESS_READER_CONFIG_INVALID"); };
    if (config === null || typeof config !== "object") invalid();
    // Every field, and every chain's fields, read exactly once into a frozen
    // copy: the checks, the test-mode guard and the stored wiring all use the
    // same snapshot, so a getter cannot show one wiring and store another.
    let snap: {
      cadenas: readonly CadenaLecturaStyx[]; ahoraMs: unknown; maxEdadMs: unknown; limiteCadenaMs: unknown;
      maxIntentosLectura: unknown; despliegueFijado: unknown; idDespliegueEsperado: unknown;
    };
    try {
      const { cadenas, ahoraMs, maxEdadMs, limiteCadenaMs, maxIntentosLectura, despliegueFijado, idDespliegueEsperado } =
        config as unknown as Record<string, unknown>;
      if (!Array.isArray(cadenas)) invalid();
      const copia = Array.from(cadenas as unknown[], (cadena) => {
        if (cadena === null || typeof cadena !== "object") invalid();
        const { chain, rpc, contract, writer } = cadena as Record<string, unknown>;
        return Object.freeze({ chain, rpc, contract, writer }) as unknown as CadenaLecturaStyx;
      });
      snap = { cadenas: Object.freeze(copia), ahoraMs, maxEdadMs, limiteCadenaMs, maxIntentosLectura, despliegueFijado, idDespliegueEsperado };
    } catch {
      invalid();
    }
    const { cadenas, ahoraMs, maxEdadMs, limiteCadenaMs, maxIntentosLectura, despliegueFijado, idDespliegueEsperado } = snap!;
    const n = cadenas.length;
    if ((n !== 3 && n !== 2)
      || new Set(cadenas.map((cadena) => cadena.chain)).size !== n
      || (n === 2 && cadenas.some((cadena) => cadena.chain === "ALERA"))
      || cadenas.some((cadena) => !CHAINS.has(cadena.chain)
        || typeof cadena.contract !== "string" || !ADDRESS.test(cadena.contract)
        || typeof cadena.writer !== "string" || !ADDRESS.test(cadena.writer)
        || cadena.rpc === null || typeof cadena.rpc !== "object"
        || typeof cadena.rpc.call !== "function" || typeof cadena.rpc.getBlockByNumber !== "function")
      // Three chains behind one RPC object are one source, not a quorum.
      || new Set(cadenas.map((cadena) => cadena.rpc)).size !== n
      || (ahoraMs !== undefined && typeof ahoraMs !== "function")
      || typeof maxEdadMs !== "number" || !Number.isSafeInteger(maxEdadMs) || maxEdadMs < 1 || maxEdadMs > MAX_EDAD_TOPE_MS
      || (limiteCadenaMs !== undefined && (typeof limiteCadenaMs !== "number" || !Number.isSafeInteger(limiteCadenaMs)
        || limiteCadenaMs < 1 || limiteCadenaMs > 120_000))
      || (maxIntentosLectura !== undefined && (typeof maxIntentosLectura !== "number"
        || !Number.isSafeInteger(maxIntentosLectura) || maxIntentosLectura < 1 || maxIntentosLectura > 1024))) {
      invalid();
    }
    if (n === 2) {
      // Two chains only when the pinned deployment itself says TEST_2_OF_2.
      exigirDespliegueModoPrueba(despliegueFijado as DespliegueStyxPublicado, idDespliegueEsperado as string, cadenas);
    } else if (despliegueFijado !== undefined || idDespliegueEsperado !== undefined) {
      invalid();
    }
    this.#modo = n === 3 ? "2_OF_3" : "TEST_2_OF_2";
    this.#cadenas = cadenas;
    this.#ahora = (ahoraMs as (() => number) | undefined) ?? Date.now;
    this.#maxEdad = maxEdadMs as number;
    this.#maxIntentos = (maxIntentosLectura as number | undefined) ?? 64;
    this.#limiteCadena = (limiteCadenaMs as number | undefined) ?? 10_000;
  }

  /** Under which quorum every read of this reader is made. */
  public get modo(): ModoTestigo {
    return this.#modo;
  }

  /** "2 of 2, test mode" or "2 of 3": print it in every report built on this reader. */
  public get etiquetaModo(): string {
    return etiquetaModoTestigo(this.#modo);
  }

  /**
   * The quorum value under `key` with its entry times, or null when agreed
   * unwritten. A value carries its `modo`; a null (and every value-only read)
   * is labeled by this reader's `modo`, which reports must print.
   */
  public async leerClaveConTiempos(key: string): Promise<EntradaConTiempos | null> {
    if (typeof key !== "string" || !BYTES32.test(key)) throw new Error("CHAIN_WITNESS_KEY_INVALID");
    const now = this.#ahora();
    if (!Number.isSafeInteger(now)) throw new Error("CHAIN_WITNESS_CLOCK_INVALID");
    return leerEntradaQuorum(this.#cadenas, key, now, this.#maxEdad, this.#limiteCadena);
  }

  /** The quorum value under `key`, or null when agreed unwritten. */
  public async leerClave(key: string): Promise<string | null> {
    return (await this.leerClaveConTiempos(key))?.value ?? null;
  }

  /**
   * The lowest attempt of `kind` under `lockKey` whose value passes
   * `validator`, with its entry times. Attempts are numbered 0, 1, 2, ...
   * without gaps; the scan stops at the first agreed-unwritten number.
   */
  public async leerPrimeroValidoConTiempos(
    lockKey: string,
    kind: TipoIntento,
    validator: (value: string, n: number) => boolean | Promise<boolean>,
  ): Promise<(EntradaConTiempos & { readonly n: number }) | null> {
    if (typeof validator !== "function") throw new Error("CHAIN_WITNESS_VALIDATOR_REQUIRED");
    for (let n = 0; n < this.#maxIntentos; n += 1) {
      const entry = await this.leerClaveConTiempos(claveIntento(lockKey, kind, n));
      if (entry === null) return null;
      if (await validator(entry.value, n)) return Object.freeze({ n, ...entry });
    }
    throw new Error("CHAIN_WITNESS_SCAN_LIMIT_REACHED");
  }
}
