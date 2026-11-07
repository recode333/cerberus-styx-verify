// The Styx deployment id: one 64-hex value naming exactly which chains,
// contracts, writer and receipt key a record belongs to. Receipts,
// statements and acceptances carry it, so a record from a test network can
// never be taken for one from another set of chains.
//
//   deploymentId = sha256(RFC 8785 canonical JSON of
//     { kind: "STYX_DEPLOYMENT", version: 1,
//       chains: [ { chain, chainId, contract, writer } for ALERA, POLYGON, SEI in that order ],
//       receiptPublicKey })
// Test mode with two chains (ALERA not yet part of the set): exactly POLYGON
// and SEI, in that order, and the object also carries mode "TEST_2_OF_2", so
// a two-chain id can never equal a three-chain one and every record names the
// weaker quorum it was made under.
// chainId is decimal text; contract and writer are lowercase 0x addresses;
// receiptPublicKey is the Ed25519 SPKI DER hex. This is a plain hash: the
// caller still checks each chain id against the network it expects.

import { createHash } from "node:crypto";

import { serializarJcs } from "./jcs.ts";
import type { CadenaTestigo } from "./lector-testigo.ts";

export interface CadenaDespliegueStyx {
  readonly chain: CadenaTestigo;
  readonly chainId: string;
  readonly contract: string;
  readonly writer: string;
}

const ORDER: readonly CadenaTestigo[] = ["ALERA", "POLYGON", "SEI"];
const ORDER_2_DE_2: readonly CadenaTestigo[] = ["POLYGON", "SEI"];
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const DECIMAL = /^[1-9][0-9]{0,19}$/u;
const ED25519_SPKI = /^302a300506032b6570032100[0-9a-f]{64}$/u;

/** Computes the deployment id; throws STYX_DEPLOYMENT_INVALID for anything malformed. */
export function idDespliegueStyx(cadenas: readonly CadenaDespliegueStyx[], receiptPublicKey: string): string {
  const bad = (): never => { throw new Error("STYX_DEPLOYMENT_INVALID"); };
  if (!Array.isArray(cadenas) || (cadenas.length !== 3 && cadenas.length !== 2) || typeof receiptPublicKey !== "string"
    || !ED25519_SPKI.test(receiptPublicKey)) {
    bad();
  }
  const pruebaDosDeDos = cadenas.length === 2;
  const order = pruebaDosDeDos ? ORDER_2_DE_2 : ORDER;
  const chains = order.map((name) => {
    const matches = cadenas.filter((cadena) => cadena !== null && typeof cadena === "object" && cadena.chain === name);
    if (matches.length !== 1) bad();
    const { chainId, contract, writer } = matches[0] as CadenaDespliegueStyx;
    if (typeof chainId !== "string" || !DECIMAL.test(chainId)
      || typeof contract !== "string" || !ADDRESS.test(contract)
      || typeof writer !== "string" || !ADDRESS.test(writer)
      || /^0x0{40}$/u.test(contract) || /^0x0{40}$/u.test(writer) || contract === writer) {
      bad();
    }
    return { chain: name, chainId, contract, writer };
  });
  if (new Set(chains.map((chain) => chain.chainId)).size !== chains.length) bad();
  const record = pruebaDosDeDos
    ? { kind: "STYX_DEPLOYMENT", version: 1, mode: "TEST_2_OF_2", chains, receiptPublicKey }
    : { kind: "STYX_DEPLOYMENT", version: 1, chains, receiptPublicKey };
  return createHash("sha256").update(serializarJcs(record), "utf8").digest("hex");
}

/** The published deployment record (deployments/*.json), as far as a reader needs it. */
export interface DespliegueStyxPublicado {
  readonly kind: "STYX_DEPLOYMENT";
  readonly version: 1;
  readonly mode?: "TEST_2_OF_2";
  readonly chains: readonly CadenaDespliegueStyx[];
  readonly receiptPublicKey: string;
  readonly deploymentId: string;
}

/** The only chain ids a two-chain test deployment may use. */
const PRUEBA_CHAIN_IDS: Readonly<Record<string, string>> = Object.freeze({ POLYGON: "80002", SEI: "1328" });

/**
 * Checks that a reader or writer may run in two-chain test mode: the pinned
 * deployment record says TEST_2_OF_2, its id recomputes, it equals the id the
 * caller pinned, it is on the two test networks, and the chains the caller
 * wired (contract and writer per chain) are exactly the record's. Throws
 * CHAIN_WITNESS_TEST_MODE_REFUSED otherwise.
 */
export function exigirDespliegueModoPrueba(
  registro: DespliegueStyxPublicado,
  idDespliegueEsperado: string,
  cadenas: readonly { readonly chain: CadenaTestigo; readonly contract: string; readonly writer: string }[],
): void {
  const refused = (): never => { throw new Error("CHAIN_WITNESS_TEST_MODE_REFUSED"); };
  if (registro === null || typeof registro !== "object" || Array.isArray(registro)) refused();
  let kind: unknown;
  let version: unknown;
  let mode: unknown;
  let chains: unknown;
  let receiptPublicKey: unknown;
  let deploymentId: unknown;
  try {
    // Each field read once, so a getter cannot answer twice.
    ({ kind, version, mode, chains, receiptPublicKey, deploymentId } = registro as unknown as Record<string, unknown>);
  } catch {
    refused();
  }
  if (kind !== "STYX_DEPLOYMENT" || version !== 1 || mode !== "TEST_2_OF_2"
    || typeof deploymentId !== "string" || deploymentId !== idDespliegueEsperado
    || !Array.isArray(chains) || chains.length !== 2 || !Array.isArray(cadenas) || cadenas.length !== 2) {
    refused();
  }
  let copia: CadenaDespliegueStyx[] = [];
  let wiring: { chain: unknown; contract: unknown; writer: unknown }[] = [];
  try {
    copia = Array.from(chains as unknown[], (chain) => {
      if (chain === null || typeof chain !== "object") refused();
      const { chain: name, chainId, contract, writer } = chain as Record<string, unknown>;
      return { chain: name, chainId, contract, writer } as CadenaDespliegueStyx;
    });
    wiring = Array.from(cadenas as unknown[], (cadena) => {
      if (cadena === null || typeof cadena !== "object") refused();
      const { chain, contract, writer } = cadena as Record<string, unknown>;
      return { chain, contract, writer };
    });
  } catch {
    refused();
  }
  let id = "";
  try {
    id = idDespliegueStyx(copia, receiptPublicKey as string);
  } catch {
    refused();
  }
  if (id !== deploymentId) refused();
  for (const chain of copia) {
    if (PRUEBA_CHAIN_IDS[chain.chain] !== chain.chainId) refused();
    const wired = wiring.filter((cadena) => cadena.chain === chain.chain);
    if (wired.length !== 1 || wired[0]!.contract !== chain.contract || wired[0]!.writer !== chain.writer) refused();
  }
}
