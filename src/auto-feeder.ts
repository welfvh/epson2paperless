import fs from "node:fs";
import path from "node:path";
import https from "node:https";
import { createHash } from "node:crypto";
import type { TLSSocket } from "node:tls";
import { SaxesParser } from "saxes";
import type { ScanAdmission } from "./scan-admission.js";
import { createLogger } from "./logger.js";

const log = createLogger("auto-feeder");
const SCAN = "http://schemas.hp.com/imaging/escl/2011/05/03";
const PWG = "http://www.pwg.org/schemas/2010/12/sm";

export interface FeederStatus {
  printerIp: string;
  state: string;
  adf: "empty" | "loaded" | "unknown";
}

export function parseFeederStatus(xml: string, printerIp: string): FeederStatus {
  const parser = new SaxesParser({ xmlns: true });
  let depth = 0;
  let field: "state" | "adf" | null = null;
  const values = { state: "", adf: "" };
  const seen = new Set<string>();
  parser.on("doctype", () => {
    throw new Error("Scanner status must not contain a DOCTYPE");
  });
  parser.on("opentag", (tag) => {
    depth++;
    if (depth === 1 && (tag.uri !== SCAN || tag.local !== "ScannerStatus")) {
      throw new Error("Expected an eSCL ScannerStatus document");
    }
    if (depth !== 2) {
      if (field !== null) throw new Error("Nested scanner status value");
      return;
    }
    field =
      tag.uri === PWG && tag.local === "State"
        ? "state"
        : tag.uri === SCAN && tag.local === "AdfState"
          ? "adf"
          : null;
    if (field !== null) {
      if (seen.has(field)) throw new Error("Duplicate scanner status value");
      seen.add(field);
    }
  });
  parser.on("text", (text) => {
    if (field !== null) values[field] += text;
  });
  parser.on("cdata", (text) => {
    if (field !== null) values[field] += text;
  });
  parser.on("closetag", () => {
    if (depth === 2) field = null;
    depth--;
  });
  parser.write(xml).close();
  if (!seen.has("state") || !seen.has("adf")) throw new Error("Incomplete scanner status");
  return {
    printerIp,
    state: values.state.trim(),
    adf:
      values.adf.trim() === "ScannerAdfEmpty"
        ? "empty"
        : values.adf.trim() === "ScannerAdfLoaded"
          ? "loaded"
          : "unknown",
  };
}

export function readFeederStatus(
  printerIp: string,
  fingerprint: string,
  signal: AbortSignal,
): Promise<FeederStatus> {
  return new Promise((resolve, reject) => {
    const request = https.get(
      {
        host: printerIp,
        port: 443,
        path: "/eSCL/ScannerStatus",
        // Epson uses a self-signed certificate. Accept only the configured SHA-256 pin below.
        rejectUnauthorized: false,
        signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]),
      },
      (response) => {
        const raw = (response.socket as TLSSocket).getPeerCertificate().raw;
        const actual = raw && createHash("sha256").update(raw).digest("hex").toUpperCase();
        if (actual !== fingerprint.replaceAll(":", "").toUpperCase()) {
          response.destroy();
          reject(new Error("Feeder status certificate mismatch"));
          return;
        }
        if (response.statusCode !== 200) {
          response.destroy();
          reject(new Error(`Feeder status HTTP ${response.statusCode}`));
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 65536) {
            response.destroy(new Error("Scanner status exceeds 64 KiB"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", reject);
        response.on("aborted", () => reject(new Error("Scanner status response interrupted")));
        response.on("end", () => {
          try {
            resolve(parseFeederStatus(Buffer.concat(chunks).toString("utf8"), printerIp));
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    request.on("error", reject);
  });
}

interface Options {
  journalPath: string;
  admission: Pick<ScanAdmission, "isBusy" | "reserve" | "commit">;
  readStatus(signal: AbortSignal): Promise<FeederStatus>;
  scan(status: FeederStatus): Promise<void>;
  now?: () => number;
}

export function createFeederMonitor(options: Options) {
  const now = options.now ?? Date.now;
  fs.mkdirSync(path.dirname(options.journalPath), { recursive: true, mode: 0o700 });
  let phase: "unarmed" | "armed" | "claimed" = "unarmed";
  if (fs.existsSync(options.journalPath)) {
    const lines = fs.readFileSync(options.journalPath, "utf8").split("\n");
    if (lines.pop() !== "")
      throw new Error("Incomplete feeder journal; inspect it before resuming automatic scans");
    for (const line of lines) {
      const entry: unknown = JSON.parse(line);
      if (
        typeof entry !== "object" ||
        entry === null ||
        !("phase" in entry) ||
        (entry.phase !== "armed" && entry.phase !== "claimed")
      ) {
        throw new Error("Invalid feeder journal; inspect it before resuming automatic scans");
      }
      phase = entry.phase;
    }
  }
  const abort = new AbortController();
  let stopped = false;
  let polling = false;
  let loadedSince: number | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  function persist(next: "armed" | "claimed") {
    try {
      fs.appendFileSync(
        options.journalPath,
        JSON.stringify({ phase: next, at: new Date(now()).toISOString() }) + "\n",
        { mode: 0o600, flush: true },
      );
      phase = next;
    } catch (error) {
      stop();
      throw new Error(
        "Automatic feeder stopped: journal write failed. Fix storage, then restart; panel scanning remains available.",
        { cause: error },
      );
    }
  }
  async function tick(): Promise<void> {
    if (stopped || polling) return;
    if (options.admission.isBusy()) {
      loadedSince = null;
      return;
    }
    polling = true;
    try {
      const status = await options.readStatus(abort.signal);
      if (stopped || options.admission.isBusy()) {
        loadedSince = null;
        return;
      }
      if (status.adf === "empty") {
        loadedSince = null;
        if (phase !== "armed") persist("armed");
        return;
      }
      if (status.adf !== "loaded" || status.state !== "Idle" || phase !== "armed") {
        loadedSince = null;
        return;
      }
      loadedSince ??= now();
      if (now() - loadedSince < 3000) return;
      const release = options.admission.reserve();
      try {
        persist("claimed");
      } catch (error) {
        release();
        throw error;
      }
      loadedSince = null;
      log.info("Paper loaded for 3 seconds; starting one feeder scan");
      const scan = Promise.resolve().then(() => options.scan(status));
      options.admission.commit(scan);
      void scan.catch((error: unknown) => {
        log.error(
          "Automatic scan failed. Original bytes are retained; inspect the scan log, then remove and reinsert remaining pages to retry.",
          error,
        );
      });
    } finally {
      polling = false;
    }
  }
  function stop() {
    stopped = true;
    clearTimeout(timer);
    abort.abort();
  }
  function start() {
    const poll = async () => {
      try {
        await tick();
      } catch (error) {
        if (!stopped)
          log.warn("Cannot read feeder status; keeping the current batch state and waiting", error);
      }
      if (!stopped)
        timer = setTimeout(() => {
          void poll();
        }, 1000);
    };
    void poll();
  }
  return { tick, start, stop };
}
