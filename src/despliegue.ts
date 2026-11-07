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
