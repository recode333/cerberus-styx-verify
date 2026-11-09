// Box start check over the read-only RPC client, end to end on
// loopback: two fake test chains speak JSON-RPC over HTTPS, the real
// ClienteRpcLectura reads them, the real LectorTestigoStyx (2 of 2, test
// mode) checks they agree, and verificarArranqueCaja compares a box log with
// every seal. Runs WITHOUT the network guard (its own npm step; every socket
// is 127.0.0.1). Certificates are made at run time and deleted after.
// Synthetic values only.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net, { type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { after } from "node:test";

import { verificarArranqueCaja } from "../src/arranque-caja.ts";
import { idDespliegueStyx, type CadenaDespliegueStyx } from "../src/despliegue.ts";
import { LectorTestigoStyx, SELECTOR_GET_ONE_ENTRY_LOG } from "../src/lector-testigo.ts";
import { ClienteRpcLectura, METODOS_RPC_LECTURA } from "../src/rpc-lectura.ts";
import { claveSelloDiarioHades, claveSelloHades, valorSelloDiarioHades, valorSelloHades } from "../src/sello-hades.ts";

const dir = mkdtempSync(join(tmpdir(), "styx-rpc-"));
after(() => rmSync(dir, { recursive: true, force: true }));
const ossl = (...args: string[]): void => {
  execFileSync("openssl", args, { cwd: dir, stdio: "ignore" });
};
ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-subj", "/CN=rpc-ca",
  "-keyout", "ca.key", "-out", "ca.crt", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign");
ossl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=rpc", "-keyout", "rpc.key", "-out", "rpc.csr");
writeFileSync(join(dir, "rpc.ext"), "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n");
ossl("x509", "-req", "-in", "rpc.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-days", "2", "-out", "rpc.crt", "-extfile", "rpc.ext");
const f = (name: string): string => readFileSync(join(dir, name), "utf8");

const h = (label: string): string => createHash("sha256").update(label).digest("hex");
const BOX = h("box-1");
const WRITER = `0x${"0a".repeat(20)}`;
const CONTRACTS = { POLYGON: `0x${"0b".repeat(20)}`, SEI: `0x${"0c".repeat(20)}` };
const PUB = `302a300506032b6570032100${"11".repeat(32)}`;
const NOW_S = 1_800_000_000;

/** One fake test chain: OneEntryLog entries of WRITER, served as JSON-RPC over HTTPS on loopback. */
async function cadena(chainId: number, opts: { delayMs?: number; huge?: boolean } = {}) {
  const entries = new Map<string, string>();
  const methods: string[] = [];
  const server = https.createServer({ cert: f("rpc.crt"), key: f("rpc.key") }, (req, res) => {
    let body = "";
    req.on("data", (c) => { body += String(c); });
    req.on("end", async () => {
      const msg = JSON.parse(body) as { id: number; method: string; params: unknown[] };
      methods.push(msg.method);
      if (opts.delayMs !== undefined && msg.method === "eth_call") await new Promise((r) => setTimeout(r, opts.delayMs));
      let result: unknown;
      if (msg.method === "eth_chainId") result = `0x${chainId.toString(16)}`;
      else if (msg.method === "eth_getBlockByNumber") result = { timestamp: `0x${NOW_S.toString(16)}` };
      else if (msg.method === "eth_call") {
        const data = (msg.params[0] as { data: string }).data;
        assert.equal(data.slice(0, 10), SELECTOR_GET_ONE_ENTRY_LOG);
        assert.equal(`0x${data.slice(34, 74)}`, WRITER);
        const key = `0x${data.slice(74, 138)}`;
        const value = entries.get(key);
        result = value === undefined ? `0x${"0".repeat(128)}` : `0x${value.slice(2)}${(NOW_S - 60).toString(16).padStart(64, "0")}`;
      } else if (msg.method === "eth_blockNumber") result = "0x10";
      else if (msg.method === "eth_getLogs") result = [];
      else result = null;
      const text = JSON.stringify({ jsonrpc: "2.0", id: msg.id, result });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(opts.huge === true ? `${text}${" ".repeat(2 << 20)}` : text);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  after(() => server.close());
  const port = (server.address() as AddressInfo).port;
  return { entries, methods, url: `https://127.0.0.1:${port}/rpc` };
}

function lector(polygon: ClienteRpcLectura, sei: ClienteRpcLectura): LectorTestigoStyx {
  const chains: CadenaDespliegueStyx[] = [
    { chain: "POLYGON", chainId: "80002", contract: CONTRACTS.POLYGON, writer: WRITER },
    { chain: "SEI", chainId: "1328", contract: CONTRACTS.SEI, writer: WRITER },
  ];
  const deploymentId = idDespliegueStyx(chains, PUB);
  return new LectorTestigoStyx({
    cadenas: [
      { chain: "POLYGON", rpc: polygon, contract: CONTRACTS.POLYGON, writer: WRITER },
      { chain: "SEI", rpc: sei, contract: CONTRACTS.SEI, writer: WRITER },
    ],
    despliegueFijado: { kind: "STYX_DEPLOYMENT", version: 1, mode: "TEST_2_OF_2", chains, receiptPublicKey: PUB, deploymentId },
    idDespliegueEsperado: deploymentId,
    ahoraMs: () => NOW_S * 1000,
    maxEdadMs: 3_600_000,
    limiteCadenaMs: 2000,
  });
}

const cliente = (url: string, chainId: number, over: Record<string, unknown> = {}) =>
  new ClienteRpcLectura({ urls: [url], chainIdEsperado: chainId, caPem: f("ca.crt"), limiteEsperaMs: 3000, ...over });

/** A box log of chain hashes h(head-1) .. h(head-k). */
function log(hashes: string[]) {
  return {
    cabeza: async () => (hashes.length === 0 ? null : { seq: hashes.length, sha256: hashes[hashes.length - 1] as string }),
    shaEn: async (seq: number) => (Number.isSafeInteger(seq) && seq >= 1 && seq <= hashes.length ? hashes[seq - 1] as string : null),
    seqDeSha: async (sha: string) => (hashes.indexOf(sha) < 0 ? null : hashes.indexOf(sha) + 1),
  };
}

const HASHES = [1, 2, 3, 4, 5, 6].map((i) => h(`head-${i}`));

/** Writes the same seals on both chains: restore seals at heads 2 and 4, daily seals at heads 3 and 5. */
function sellar(...chains: { entries: Map<string, string> }[]) {
  for (const c of chains) {
    c.entries.set(claveSelloHades(BOX, 0), valorSelloHades({ seq: 2, sha256: HASHES[1] as string }, "RESTAURACION"));
    c.entries.set(claveSelloHades(BOX, 1), valorSelloHades({ seq: 4, sha256: HASHES[3] as string }, "RESTAURACION"));
    c.entries.set(claveSelloDiarioHades(BOX, 0), valorSelloDiarioHades({ seq: 3, sha256: HASHES[2] as string }));
    c.entries.set(claveSelloDiarioHades(BOX, 1), valorSelloDiarioHades({ seq: 5, sha256: HASHES[4] as string }));
  }
}

test("RA-01 matching seals on both test chains: the box passes, labeled 2 of 2 test mode, reading only allowlisted methods", async () => {
  const p = await cadena(80002);
  const s = await cadena(1328);
  sellar(p, s);
  const r = await verificarArranqueCaja(lector(cliente(p.url, 80002), cliente(s.url, 1328)), BOX, log(HASHES));
  assert.equal(r.modo, "TEST_2_OF_2");
  assert.match(r.etiquetaModo, /2 of 2/u);
  assert.equal(r.restauracion?.n, 1);
  assert.equal(r.diario?.sha256, HASHES[4]);
  for (const m of [...p.methods, ...s.methods]) assert.ok((METODOS_RPC_LECTURA as readonly string[]).includes(m), m);
  // A never-sealed box passes with nothing to prove.
  const empty = await verificarArranqueCaja(lector(cliente(p.url, 80002), cliente(s.url, 1328)), h("box-2"), log(HASHES));
  assert.equal(empty.restauracion, null);
  assert.equal(empty.diario, null);
});

test("RA-02 a missing seal, a forged earlier seal, or a changed log keeps the box closed", async () => {
  const p = await cadena(80002);
  const s = await cadena(1328);
  sellar(p, s);
  const L = () => lector(cliente(p.url, 80002), cliente(s.url, 1328));
  // Log shortened below the newest restore seal.
  await assert.rejects(verificarArranqueCaja(L(), BOX, log(HASHES.slice(0, 3))), /HADES_LOG_SHORTENED/u);
  // An earlier record rewritten.
  const rewritten = [...HASHES];
  rewritten[1] = h("forged");
  await assert.rejects(verificarArranqueCaja(L(), BOX, log(rewritten)), /HADES_LOG_REWRITTEN/u);
  // A forged earlier seal on both chains (value for another head at seal 0).
  for (const c of [p, s]) c.entries.set(claveSelloHades(BOX, 0), valorSelloHades({ seq: 2, sha256: h("other") }, "RESTAURACION"));
  await assert.rejects(verificarArranqueCaja(L(), BOX, log(HASHES)), /HADES_LOG_REWRITTEN/u);
  sellar(p, s);
  // A daily seal whose head is not in the log.
  for (const c of [p, s]) c.entries.set(claveSelloDiarioHades(BOX, 0), valorSelloDiarioHades({ seq: 3, sha256: h("not-in-log") }));
  await assert.rejects(verificarArranqueCaja(L(), BOX, log(HASHES)), /HADES_LOG_REWRITTEN/u);
  sellar(p, s);
  // A missing earlier seal (gap) in the daily series: six daily seals, number 3 missing on both chains.
  for (const c of [p, s]) {
    for (let i = 0; i < 6; i += 1) c.entries.set(claveSelloDiarioHades(BOX, i), valorSelloDiarioHades({ seq: i + 1, sha256: HASHES[i] as string }));
    c.entries.delete(claveSelloDiarioHades(BOX, 3));
  }
  await assert.rejects(verificarArranqueCaja(L(), BOX, log(HASHES)), /HADES_SEAL_GAP/u);
  // Limit (documented): seals are written gaplessly, so when BOTH chains hide every seal from
  // number k on, the box sees an older newest seal. Two chains agreeing on a lie is outside
  // the 2-of-2 test model.
});

test("RA-03 chains that disagree, a slow chain, an oversized answer, or a wrong chain id keep the box closed", async () => {
  const p = await cadena(80002);
  const s = await cadena(1328);
  sellar(p, s);
  // Disagreement: the newest restore seal differs on Sei.
  s.entries.set(claveSelloHades(BOX, 1), valorSelloHades({ seq: 4, sha256: h("other") }, "RESTAURACION"));
  await assert.rejects(verificarArranqueCaja(lector(cliente(p.url, 80002), cliente(s.url, 1328)), BOX, log(HASHES)));
  // Slow chain (answers after the 2 s per-chain limit).
  const slow = await cadena(1328, { delayMs: 3500 });
  sellar(slow);
  await assert.rejects(verificarArranqueCaja(lector(cliente(p.url, 80002), cliente(slow.url, 1328, { limiteEsperaMs: 5000 })), BOX, log(HASHES)));
  // Oversized answer.
  const huge = await cadena(1328, { huge: true });
  sellar(huge);
  await assert.rejects(verificarArranqueCaja(lector(cliente(p.url, 80002), cliente(huge.url, 1328)), BOX, log(HASHES)));
  // A URL answering another chain id is never used.
  const wrong = await cadena(137);
  sellar(wrong);
  await assert.rejects(cliente(wrong.url, 1328).call({ to: CONTRACTS.SEI, data: "0x" }, "finalized"), /STYX_RPC_UNAVAILABLE/u);
  assert.deepEqual(wrong.methods, ["eth_chainId"]);
});

test("RA-04 the RPC client can only read: every other method is refused before any connection", async () => {
  const p = await cadena(80002);
  const c = cliente(p.url, 80002);
  for (const m of ["eth_sendRawTransaction", "eth_sendTransaction", "eth_sign", "personal_sign", "eth_signTypedData_v4",
    "eth_accounts", "debug_traceTransaction", "admin_peers", "eth_chainid", "ETH_CALL", "", "__proto__", "toString"]) {
    await assert.rejects(c.llamar(m, []), /STYX_RPC_METHOD_REFUSED/u, m);
  }
  assert.equal(p.methods.length, 0, "nothing reached the chain");
  await assert.rejects(c.llamar("eth_call", "x" as never), /STYX_RPC_PARAMS_INVALID/u);
  await assert.rejects(c.call({ to: "0x12", data: "0x" }, "finalized"), /STYX_RPC_PARAMS_INVALID/u);
  await assert.rejects(c.call({ to: CONTRACTS.POLYGON, data: "0x" }, "latest" as never), /STYX_RPC_PARAMS_INVALID/u);
  assert.equal(p.methods.length, 0);
});

test("RA-05 config: https only, no credentials, query or fragment in URLs, 1 to 4 URLs, safe key header, http CONNECT proxy only", () => {
  const ok = { urls: ["https://127.0.0.1:1/rpc"], chainIdEsperado: 1328 };
  assert.ok(new ClienteRpcLectura(ok));
  for (const over of [
    { urls: ["http://127.0.0.1:1/rpc"] },
    { urls: ["https://user:pw@127.0.0.1:1/rpc"] },
    { urls: ["https://127.0.0.1:1/rpc?key=abc"] },
    { urls: ["https://127.0.0.1:1/rpc#x"] },
    { urls: [] },
    { urls: ["https://a.invalid", "https://b.invalid", "https://c.invalid", "https://d.invalid", "https://e.invalid"] },
    { chainIdEsperado: 0 },
    { chainIdEsperado: 1.5 },
    { cabeceraClave: { nombre: "Host", valor: "x" } },
    { cabeceraClave: { nombre: "x-api-key", valor: "a b" } },
    { cabeceraClave: { nombre: "bad header", valor: "x" } },
    { caPem: "not pem" },
    { proxy: "https://127.0.0.1:3128" },
    { proxy: "http://user:pw@127.0.0.1:3128" },
    { limiteEsperaMs: 999 },
    { maxRespuestaBytes: 100 },
  ]) {
    assert.throws(() => new ClienteRpcLectura({ ...ok, ...over } as never), /STYX_RPC_CONFIG_INVALID/u, JSON.stringify(over));
  }
});

test("RA-06 no proxy by default even with proxy variables set; an explicit CONNECT proxy keeps TLS end to end; the key header reaches the RPC host only", async () => {
  const p = await cadena(80002);
  // Environment proxy variables are ignored by default.
  const saved = { ...process.env };
  process.env["HTTPS_PROXY"] = "http://127.0.0.1:9";
  process.env["https_proxy"] = "http://127.0.0.1:9";
  try {
    assert.equal(await cliente(p.url, 80002).llamar("eth_blockNumber", []), "0x10");
    assert.ok(p.methods.includes("eth_chainId"), "reached the chain directly");
  } finally {
    process.env = saved;
  }
  // An explicit CONNECT proxy: it only sees the tunnel target, never the key or the body.
  const seen: string[] = [];
  const tunnels: net.Socket[] = [];
  const proxy = http.createServer();
  proxy.on("connect", (req, client, head) => {
    seen.push(String(req.url));
    const [host, port] = String(req.url).split(":");
    tunnels.push(client as net.Socket);
    const up = net.connect(Number(port), host, () => {
      tunnels.push(up);
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      up.write(head);
      up.pipe(client);
      client.pipe(up);
    });
    client.on("data", (d: Buffer) => seen.push(d.toString("latin1")));
  });
  await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  after(() => {
    for (const t of tunnels) t.destroy();
    proxy.close();
  });
  const proxyUrl = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;
  const viaProxy = cliente(p.url, 80002, { proxy: proxyUrl, cabeceraClave: { nombre: "x-api-key", valor: "SYNTHETIC-KEY-123" } });
  const before = p.methods.length;
  await viaProxy.getBlockByNumber("finalized");
  assert.ok(p.methods.length > before, "the chain answered through the tunnel");
  assert.ok(seen.some((x) => /^127\.0\.0\.1:\d+$/u.test(x)), "proxy saw only host:port");
  assert.ok(!seen.join("").includes("SYNTHETIC-KEY-123"), "the key never crossed the proxy in clear");
  assert.ok(!seen.join("").includes("eth_getBlockByNumber"), "the body never crossed the proxy in clear");
  // Errors never carry the URL or the key.
  const dead = cliente("https://127.0.0.1:1/rpc", 80002, { cabeceraClave: { nombre: "x-api-key", valor: "SYNTHETIC-KEY-123" } });
  await assert.rejects(dead.llamar("eth_blockNumber", []), (e: Error) => {
    assert.equal(e.message, "STYX_RPC_UNAVAILABLE");
    return true;
  });
});

test("RA-07 failover and answer checks: a bad first URL falls through to a good one; wrong id or envelope is refused", async () => {
  const good = await cadena(1328);
  const c = new ClienteRpcLectura({ urls: ["https://127.0.0.1:1/rpc", good.url], chainIdEsperado: 1328, caPem: f("ca.crt"), limiteEsperaMs: 2000 });
  assert.equal(await c.llamar("eth_chainId", []), "0x530");
  const bad = https.createServer({ cert: f("rpc.crt"), key: f("rpc.key") }, (req, res) => {
    let body = "";
    req.on("data", (d) => { body += String(d); });
    req.on("end", () => {
      const msg = JSON.parse(body) as { id: number; method: string };
      res.writeHead(200, { "content-type": "application/json" });
      if (msg.method === "eth_chainId") res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: "0x530" }));
      else res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id + 1, result: "0x1" }));
    });
  });
  await new Promise<void>((resolve) => bad.listen(0, "127.0.0.1", resolve));
  after(() => bad.close());
  const wrongId = cliente(`https://127.0.0.1:${(bad.address() as AddressInfo).port}/`, 1328);
  await assert.rejects(wrongId.llamar("eth_blockNumber", []), /STYX_RPC_UNAVAILABLE/u);
  // Chunked logs: ranges never exceed the step.
  const logs = await cliente(good.url, 1328).getLogsEnTramos({ address: CONTRACTS.SEI, topics: [], desde: 0n, hasta: 2500n, tramo: 1000 });
  assert.equal(logs.length, 0);
  assert.equal(good.methods.filter((m) => m === "eth_getLogs").length, 3);
});

test("RA-08 certificate checks stay on: a host whose certificate does not chain to the trusted roots is never read", async () => {
  const p = await cadena(80002);
  // System roots only (no caPem): the loopback test CA is not trusted.
  const c = new ClienteRpcLectura({ urls: [p.url], chainIdEsperado: 80002, limiteEsperaMs: 3000 });
  await assert.rejects(c.llamar("eth_blockNumber", []), /STYX_RPC_UNAVAILABLE/u);
  assert.equal(p.methods.length, 0);
});
