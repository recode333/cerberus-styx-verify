// Minimal read-only JSON-RPC client for a box's start check.
// It can only read: the method allowlist is chain id, block number, block by
// number (for the finalized timestamp the reader needs), code, call and logs.
// Every other method, including any sending or signing method, is refused in
// code before anything leaves the process.
//
// - Endpoints only from the box config: one to four https URLs per chain,
//   certificate checks on, no credentials, query or fragment in the URL.
//   Tried in order; the first that answers correctly wins.
// - An optional provider key travels in one request header taken from a
//   separate secret file; it never appears in errors.
// - No proxy by default (environment proxy variables are ignored). If the
//   network requires one, `proxy` is an http CONNECT proxy from the config;
//   TLS stays end to end to the RPC host.
// - Each URL must answer the expected chain id before its first read.
// - Hard timeout and a size cap on every answer; a wrong JSON-RPC envelope,
//   id or type is refused. Errors are fixed codes only.
// - getLogs reads are split into block ranges (public RPCs cap log ranges)
//   with a cap on entries.

import http from "node:http";
import https from "node:https";
import type { Socket } from "node:net";
import tls from "node:tls";

import type { RpcLecturaStyx } from "./lector-testigo.ts";

export const METODOS_RPC_LECTURA = Object.freeze([
  "eth_chainId",
  "eth_blockNumber",
  "eth_getBlockByNumber",
  "eth_getCode",
  "eth_call",
  "eth_getLogs",
] as const);
export type MetodoRpcLectura = (typeof METODOS_RPC_LECTURA)[number];
const METODOS: ReadonlySet<string> = new Set(METODOS_RPC_LECTURA);

export interface ClienteRpcLecturaConfig {
  /** 1 to 4 https URLs for ONE chain, from the box config. */
  readonly urls: readonly string[];
  /** The chain id every URL must answer (e.g. 80002, 1328). */
  readonly chainIdEsperado: number;
  /** Optional provider key, read from a separate secret file: one header name and value. */
  readonly cabeceraClave?: { readonly nombre: string; readonly valor: string };
  /** Optional CA certificates (PEM) that replace the system roots for these hosts. */
  readonly caPem?: string;
  /** Optional http://host:port CONNECT proxy. Default: none. */
  readonly proxy?: string;
  /** Per-request timeout, 1000 to 60000 ms. Default 10000. */
  readonly limiteEsperaMs?: number;
  /** Answer size cap, 1 KiB to 8 MiB. Default 1 MiB. */
  readonly maxRespuestaBytes?: number;
}

interface Destino {
  readonly host: string;
  readonly port: number;
  readonly path: string;
}

const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const DATA = /^0x(?:[0-9a-f]{2})*$/u;
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/u;
const HEADER_VALUE = /^[\x21-\x7e]{1,512}$/u;
const FORBIDDEN_HEADERS: ReadonlySet<string> = new Set(["host", "content-length", "content-type", "transfer-encoding", "connection"]);

function configInvalida(): never {
  throw new Error("STYX_RPC_CONFIG_INVALID");
}

function destino(url: unknown): Destino {
  if (typeof url !== "string" || url.length > 2048 || url.includes("?") || url.includes("#")) configInvalida();
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    configInvalida();
  }
  if (u.protocol !== "https:" || u.username !== "" || u.password !== "" || u.hostname === "") configInvalida();
  const host = u.hostname.startsWith("[") ? u.hostname.slice(1, -1) : u.hostname;
  return Object.freeze({ host, port: u.port === "" ? 443 : Number(u.port), path: u.pathname === "" ? "/" : u.pathname });
}

function entero(value: unknown, defecto: number, min: number, max: number): number {
  const v = value === undefined ? defecto : value;
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) configInvalida();
  return v;
}

export class ClienteRpcLectura implements RpcLecturaStyx {
  readonly #destinos: readonly Destino[];
  readonly #chainId: string;
  readonly #cabecera: { readonly nombre: string; readonly valor: string } | null;
  readonly #ca: string | null;
  readonly #proxy: { readonly host: string; readonly port: number } | null;
  readonly #limiteMs: number;
  readonly #maxBytes: number;
  readonly #verificados = new Set<number>();
  #id = 0;

  public constructor(config: ClienteRpcLecturaConfig) {
    if (config === null || typeof config !== "object") configInvalida();
    const { urls, chainIdEsperado, cabeceraClave, caPem, proxy } = config;
    if (!Array.isArray(urls) || urls.length < 1 || urls.length > 4) configInvalida();
    this.#destinos = Object.freeze(urls.map(destino));
    if (!Number.isSafeInteger(chainIdEsperado) || chainIdEsperado < 1) configInvalida();
    this.#chainId = `0x${chainIdEsperado.toString(16)}`;
    if (cabeceraClave !== undefined) {
      if (cabeceraClave === null || typeof cabeceraClave !== "object"
        || typeof cabeceraClave.nombre !== "string" || !HEADER_NAME.test(cabeceraClave.nombre)
        || FORBIDDEN_HEADERS.has(cabeceraClave.nombre.toLowerCase())
        || typeof cabeceraClave.valor !== "string" || !HEADER_VALUE.test(cabeceraClave.valor)) {
        configInvalida();
      }
      this.#cabecera = Object.freeze({ nombre: cabeceraClave.nombre, valor: cabeceraClave.valor });
    } else {
      this.#cabecera = null;
    }
    if (caPem !== undefined && (typeof caPem !== "string" || caPem.length > 65536 || !caPem.includes("-----BEGIN CERTIFICATE-----"))) {
      configInvalida();
    }
    this.#ca = caPem ?? null;
    if (proxy !== undefined) {
      let p: URL;
      try {
        p = new URL(proxy);
      } catch {
        configInvalida();
      }
      if (p.protocol !== "http:" || p.username !== "" || p.password !== "" || p.hostname === ""
        || (p.pathname !== "/" && p.pathname !== "") || p.search !== "" || p.hash !== "") {
        configInvalida();
      }
      this.#proxy = Object.freeze({ host: p.hostname, port: p.port === "" ? 80 : Number(p.port) });
    } else {
      this.#proxy = null;
    }
    this.#limiteMs = entero(config.limiteEsperaMs, 10_000, 1000, 60_000);
    this.#maxBytes = entero(config.maxRespuestaBytes, 1 << 20, 1024, 8 << 20);
  }

  /** One read. Only allowlisted methods; anything else is refused before any network use. */
  public async llamar(metodo: string, params: readonly unknown[]): Promise<unknown> {
    if (typeof metodo !== "string" || !METODOS.has(metodo)) throw new Error("STYX_RPC_METHOD_REFUSED");
    if (!Array.isArray(params)) throw new Error("STYX_RPC_PARAMS_INVALID");
    let cuerpoParams: string;
    try {
      cuerpoParams = JSON.stringify(params);
    } catch {
      throw new Error("STYX_RPC_PARAMS_INVALID");
    }
    if (cuerpoParams.length > 8192) throw new Error("STYX_RPC_PARAMS_INVALID");
    for (let i = 0; i < this.#destinos.length; i += 1) {
      try {
        if (!this.#verificados.has(i)) {
          const id = await this.#enviar(i, "eth_chainId", []);
          if (id !== this.#chainId) continue;
          this.#verificados.add(i);
        }
        return await this.#enviar(i, metodo, params);
      } catch {
        // Next URL; the reason never leaves this function (it may name a host).
      }
    }
    throw new Error("STYX_RPC_UNAVAILABLE");
  }

  public async getBlockByNumber(tag: "finalized"): Promise<{ readonly timestamp: unknown } | null> {
    if (tag !== "finalized") throw new Error("STYX_RPC_PARAMS_INVALID");
    const r = await this.llamar("eth_getBlockByNumber", ["finalized", false]);
    if (r === null) return null;
    if (typeof r !== "object" || Array.isArray(r)) throw new Error("STYX_RPC_ANSWER_INVALID");
    return Object.freeze({ timestamp: (r as Record<string, unknown>)["timestamp"] });
  }

  public async call(call: { readonly to: string; readonly data: string }, tag: "finalized"): Promise<string> {
    if (tag !== "finalized" || call === null || typeof call !== "object"
      || typeof call.to !== "string" || !ADDRESS.test(call.to) || typeof call.data !== "string" || !DATA.test(call.data)) {
      throw new Error("STYX_RPC_PARAMS_INVALID");
    }
    const r = await this.llamar("eth_call", [{ to: call.to, data: call.data }, "finalized"]);
    if (typeof r !== "string" || !DATA.test(r)) throw new Error("STYX_RPC_ANSWER_INVALID");
    return r;
  }

  /**
   * Logs of one contract between two blocks, read in ranges of `tramo`
   * blocks, at most `maxEntradas` entries in total.
   */
  public async getLogsEnTramos(filtro: {
    readonly address: string;
    readonly topics: readonly (string | null)[];
    readonly desde: bigint;
    readonly hasta: bigint;
    readonly tramo?: number;
    readonly maxEntradas?: number;
  }): Promise<readonly unknown[]> {
    const tramo = BigInt(entero(filtro.tramo, 1000, 1, 10_000));
    const max = entero(filtro.maxEntradas, 10_000, 1, 100_000);
    if (typeof filtro.address !== "string" || !ADDRESS.test(filtro.address)
      || typeof filtro.desde !== "bigint" || typeof filtro.hasta !== "bigint"
      || filtro.desde < 0n || filtro.hasta < filtro.desde || !Array.isArray(filtro.topics) || filtro.topics.length > 4) {
      throw new Error("STYX_RPC_PARAMS_INVALID");
    }
    const out: unknown[] = [];
    for (let from = filtro.desde; from <= filtro.hasta; from += tramo) {
      const to = from + tramo - 1n < filtro.hasta ? from + tramo - 1n : filtro.hasta;
      const r = await this.llamar("eth_getLogs", [{
        address: filtro.address,
        topics: filtro.topics,
        fromBlock: `0x${from.toString(16)}`,
        toBlock: `0x${to.toString(16)}`,
      }]);
      if (!Array.isArray(r)) throw new Error("STYX_RPC_ANSWER_INVALID");
      out.push(...r);
      if (out.length > max) throw new Error("STYX_RPC_ANSWER_TOO_LARGE");
    }
    return Object.freeze(out);
  }

  async #conectarProxy(destino: Destino): Promise<Socket> {
    const proxy = this.#proxy;
    if (proxy === null) throw new Error("no proxy");
    return new Promise<Socket>((resolve, reject) => {
      const req = http.request({
        host: proxy.host,
        port: proxy.port,
        method: "CONNECT",
        path: `${destino.host.includes(":") ? `[${destino.host}]` : destino.host}:${destino.port}`,
        agent: false,
        timeout: this.#limiteMs,
      });
      req.on("connect", (res, socket) => {
        if (res.statusCode === 200) resolve(socket);
        else {
          socket.destroy();
          reject(new Error("proxy refused"));
        }
      });
      req.on("timeout", () => req.destroy(new Error("proxy timeout")));
      req.on("error", reject);
      req.end();
    });
  }

  async #enviar(indice: number, metodo: string, params: readonly unknown[]): Promise<unknown> {
    const d = this.#destinos[indice] as Destino;
    this.#id += 1;
    const id = this.#id;
    const body = Buffer.from(JSON.stringify({ jsonrpc: "2.0", id, method: metodo, params }), "utf8");
    const tunel = this.#proxy === null ? null : await this.#conectarProxy(d);
    const texto = await new Promise<string>((resolve, reject) => {
      let terminado = false;
      const fin = (error: Error | null, valor?: string): void => {
        if (terminado) return;
        terminado = true;
        clearTimeout(reloj);
        if (error !== null || valor === undefined) {
          tunel?.destroy();
          reject(new Error("STYX_RPC_UNAVAILABLE"));
        } else {
          resolve(valor);
        }
      };
      const tlsOpts = {
        servername: d.host.includes(":") || /^[0-9.]+$/u.test(d.host) ? undefined : d.host,
        rejectUnauthorized: true,
        minVersion: "TLSv1.2" as const,
        ...(this.#ca === null ? {} : { ca: this.#ca }),
      };
      const headers: Record<string, string> = {
        "content-type": "application/json",
        "content-length": String(body.length),
        accept: "application/json",
        connection: "close",
      };
      if (this.#cabecera !== null) headers[this.#cabecera.nombre] = this.#cabecera.valor;
      const req = https.request({
        host: d.host,
        port: d.port,
        path: d.path,
        method: "POST",
        headers,
        ...tlsOpts,
        ...(tunel === null
          ? { agent: new https.Agent({ keepAlive: false, maxCachedSessions: 0 }) }
          : { agent: false, createConnection: () => tls.connect({ ...tlsOpts, socket: tunel, host: d.host }) }),
      }, (res) => {
        if (res.statusCode !== 200 || !/^application\/json(\s*;|$)/iu.test(String(res.headers["content-type"] ?? ""))) {
          res.resume();
          fin(new Error("bad status"));
          return;
        }
        const partes: Buffer[] = [];
        let total = 0;
        res.on("data", (parte: Buffer) => {
          total += parte.length;
          if (total > this.#maxBytes) {
            req.destroy();
            fin(new Error("too large"));
            return;
          }
          partes.push(parte);
        });
        res.on("end", () => fin(null, Buffer.concat(partes).toString("utf8")));
        res.on("error", (e) => fin(e));
        res.on("aborted", () => fin(new Error("aborted")));
      });
      const reloj = setTimeout(() => {
        req.destroy();
        fin(new Error("timeout"));
      }, this.#limiteMs);
      req.on("error", (e) => fin(e));
      req.end(body);
    });
    let parsed: unknown;
    try {
      parsed = JSON.parse(texto);
    } catch {
      throw new Error("STYX_RPC_ANSWER_INVALID");
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("STYX_RPC_ANSWER_INVALID");
    const r = parsed as Record<string, unknown>;
    const keys = Object.keys(r).sort().join(",");
    if (r["jsonrpc"] !== "2.0" || r["id"] !== id || (keys !== "id,jsonrpc,result" && keys !== "error,id,jsonrpc")) {
      throw new Error("STYX_RPC_ANSWER_INVALID");
    }
    if (keys === "error,id,jsonrpc") throw new Error("STYX_RPC_ERROR");
    const result = r["result"];
    if (metodo === "eth_chainId" || metodo === "eth_blockNumber") {
      if (typeof result !== "string" || !QUANTITY.test(result)) throw new Error("STYX_RPC_ANSWER_INVALID");
    }
    return result;
  }
}
