# cerberus-styx-verify

Verify code for the Styx log. Anyone can use it to check Styx records without
trusting the operator that wrote them: a fair draw, a receipt, or a seal.

It contains checking code, public test vectors and docs only. It holds no
keys, no signer, no client data and no service addresses.

## What is inside

| Module | What it checks |
| --- | --- |
| `claves-moira.ts` | The on-chain keys of Moira entries (salt commitment, salt key, owner tag, lock key, reveal slots, attempt keys) and the one canonical form of an RFC. |
| `recibo.ts` | Submission receipts signed by the operator's receipt key: canonical text, fields, Ed25519 signature under the domain `STYX-SUBMISSION-RECEIPT-V1`, and the expected deployment (a required argument). |
| `declaracion-referencia.ts` | Statements linking a client reference to an RFC, signed under the domain `STYX-CLIENT-REF-STATEMENT-V1`, for the expected deployment. |
| `lector-testigo.ts` | A read-only reader of the OneEntryLog contract on three chains (ALERA, Polygon, Sei) at each chain's finalized block. A value counts only when two fresh chains agree; each agreeing chain's stored entry time comes with it. Each chain needs its own RPC client; a chain that does not answer in time gives no vote. |
| `aceptacion-bloqueo.ts` | Moira lock acceptances signed under the domain `MOIRA-LOCK-ACCEPTANCE-V1`, for the expected deployment. |
| `despliegue.ts` | The deployment id: a hash of the chain ids, contracts, writer and receipt key that every signed record names. |
| `jcs.ts`, `keccak256.ts` | RFC 8785 canonical JSON and Keccak-256, with no dependencies. |

Every signed text uses its own domain prefix, so a signature made for one kind
of record can never be read as another kind.

## How to read entry times

Compare "written before" against the latest agreeing chain time, and "written
after" against the earliest. Compare two entries chain by chain, never across
chains. One lying or lagging chain can then only make a check fail, never pass.

## What a receipt proves

The operator accepted that write at that time. If, after the write window, an
entry of the receipt is empty on chain while every earlier entry of the same
receipt holds its value, the operator dropped an accepted write. A different
value under a receipt key counts against the operator unless it shows a
matching receipt from its durable log.

## Use

Node 24.22.1 or later, on the Node 24 line. The sources are TypeScript with
`.ts` imports. Pin this package by commit and compile it with `tsc` using
`rewriteRelativeImportExtensions` (Node does not strip types from files under
`node_modules`). The tests run from a checkout with plain `node`.

```ts
import { verificarRecibo, LectorTestigoStyx } from "cerberus-styx-verify";

const fields = verificarRecibo(receipt, operatorReceiptPublicKeyHex, expectedDeploymentId);
```

Test: `node --test test/*.test.ts`.

## License

Apache-2.0. See `LICENSE`.
