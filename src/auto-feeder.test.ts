import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createFeederMonitor, parseFeederStatus, type FeederStatus } from "./auto-feeder.js";
import { createScanAdmission } from "./scan-admission.js";
import { createInflightTracker } from "./lifecycle.js";
import { configSchema } from "./config.js";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  vi.restoreAllMocks();
});
const xml = (state: string, adf: string) =>
  `<s:ScannerStatus xmlns:s="http://schemas.hp.com/imaging/escl/2011/05/03" xmlns:p="http://www.pwg.org/schemas/2010/12/sm"><p:State>${state}</p:State><s:AdfState>${adf}</s:AdfState></s:ScannerStatus>`;

describe("feeder status boundary", () => {
  it("accepts the observed printer status with arbitrary namespace prefixes", () => {
    expect(parseFeederStatus(xml("Idle", "ScannerAdfLoaded"), "192.168.1.104")).toEqual({
      printerIp: "192.168.1.104",
      state: "Idle",
      adf: "loaded",
    });
  });
  it("does not treat unknown feeder states as empty or loaded", () => {
    expect(parseFeederStatus(xml("Idle", "ScannerAdfJam"), "ip").adf).toBe("unknown");
  });
  it.each([
    xml("Idle", "ScannerAdfLoaded").slice(0, -4),
    xml("Idle", "ScannerAdfLoaded").replace(
      "<p:State>Idle</p:State>",
      "<p:State>Idle</p:State><p:State>Processing</p:State>",
    ),
    xml("Idle", "ScannerAdfLoaded").replace(
      'xmlns:p="http://www.pwg.org/schemas/2010/12/sm"',
      'xmlns:p="wrong"',
    ),
    '<!DOCTYPE x [<!ENTITY x "Idle">]>' + xml("&x;", "ScannerAdfLoaded"),
    xml("Idle", "ScannerAdfLoaded").replace("Idle", "<p:X>Idle</p:X>"),
  ])("rejects malformed or ambiguous status before it can trigger a scan", (input) => {
    expect(() => parseFeederStatus(input, "ip")).toThrow();
  });
  it("requires a persistent absolute journal and certificate pin together", () => {
    const base = { printerIp: "192.168.1.104" };
    expect(configSchema.safeParse(base).success).toBe(true);
    expect(configSchema.safeParse({ ...base, autoFeedJournal: "/data/feed.jsonl" }).success).toBe(
      false,
    );
    expect(
      configSchema.safeParse({
        ...base,
        autoFeedJournal: "feed.jsonl",
        autoFeedCertFingerprint: Array(32).fill("AA").join(":"),
      }).success,
    ).toBe(false);
  });
});

function harness() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "feeder-test-"));
  dirs.push(dir);
  const journalPath = path.join(dir, "feed.jsonl");
  let time = 0;
  let status: FeederStatus = { printerIp: "192.168.1.104", state: "Idle", adf: "empty" };
  const admission = createScanAdmission(createInflightTracker());
  const scan = vi.fn(async () => {});
  const readStatus = vi.fn(async () => status);
  const options = { journalPath, admission, scan, readStatus, now: () => time };
  const monitor = createFeederMonitor(options);
  return {
    ...options,
    monitor,
    set: (adf: FeederStatus["adf"], state = "Idle") => {
      status = { ...status, adf, state };
    },
    advance: (ms = 3000) => {
      time += ms;
    },
    async load() {
      await monitor.tick();
      status = { ...status, adf: "loaded" };
      await monitor.tick();
      time += 3000;
    },
  };
}

describe("automatic feeder lifecycle", () => {
  it("waits for empty, debounces insertion, and persists the claim before scanning", async () => {
    const h = harness();
    h.scan.mockImplementation(async () => {
      expect(
        fs
          .readFileSync(h.journalPath, "utf8")
          .trim()
          .split("\n")
          .map((s) => JSON.parse(s).phase),
      ).toEqual(["armed", "claimed"]);
    });
    await h.load();
    expect(h.scan).not.toHaveBeenCalled();
    await h.monitor.tick();
    await Promise.resolve();
    expect(h.scan).toHaveBeenCalledTimes(1);
    await h.monitor.tick();
    h.advance();
    await h.monitor.tick();
    expect(h.scan).toHaveBeenCalledTimes(1);
  });
  it("does not scan paper present on first startup until an empty feeder is observed", async () => {
    const h = harness();
    h.set("loaded");
    await h.monitor.tick();
    h.advance(10000);
    await h.monitor.tick();
    expect(h.scan).not.toHaveBeenCalled();
  });
  it("keeps an inserted batch pending while busy, then waits 3 idle seconds", async () => {
    const h = harness();
    await h.monitor.tick();
    h.set("loaded", "Processing");
    await h.monitor.tick();
    h.advance(10000);
    await h.monitor.tick();
    expect(h.scan).not.toHaveBeenCalled();
    h.set("loaded");
    await h.monitor.tick();
    h.advance();
    await h.monitor.tick();
    expect(h.scan).toHaveBeenCalledTimes(1);
  });
  it("does not overlap a panel reservation that arrives during a status request", async () => {
    const h = harness();
    await h.load();
    let release = () => {};
    h.readStatus.mockImplementationOnce(async () => {
      release = h.admission.reserve();
      return { printerIp: "ip", state: "Idle", adf: "loaded" };
    });
    await h.monitor.tick();
    expect(h.scan).not.toHaveBeenCalled();
    release();
  });
  it("retains a failed batch claim across restart and requires removal before retry", async () => {
    const h = harness();
    h.scan.mockRejectedValueOnce(new Error("partial scan"));
    await h.load();
    await h.monitor.tick();
    await new Promise((resolve) => setImmediate(resolve));
    h.monitor.stop();
    const next = createFeederMonitor(h);
    h.advance(10000);
    await next.tick();
    h.advance();
    await next.tick();
    expect(h.scan).toHaveBeenCalledTimes(1);
    h.set("empty");
    await next.tick();
    h.set("loaded");
    await next.tick();
    h.advance();
    await next.tick();
    expect(h.scan).toHaveBeenCalledTimes(2);
    next.stop();
  });
  it("does not infer removal from a network failure", async () => {
    const h = harness();
    await h.load();
    await h.monitor.tick();
    await new Promise((resolve) => setImmediate(resolve));
    h.readStatus.mockRejectedValueOnce(new Error("network"));
    await expect(h.monitor.tick()).rejects.toThrow("network");
    h.advance(10000);
    await h.monitor.tick();
    expect(h.scan).toHaveBeenCalledTimes(1);
  });
  it("stops without scanning if the intent cannot be persisted", async () => {
    const h = harness();
    await h.load();
    fs.rmSync(h.journalPath);
    fs.mkdirSync(h.journalPath);
    await expect(h.monitor.tick()).rejects.toThrow("journal write failed");
    expect(h.scan).not.toHaveBeenCalled();
    fs.rmSync(h.journalPath, { recursive: true });
    await h.monitor.tick();
    expect(h.scan).not.toHaveBeenCalled();
    expect(h.admission.isBusy()).toBe(false);
  });
  it("does not start a scan when stopped during an outstanding status request", async () => {
    const h = harness();
    await h.load();
    h.readStatus.mockImplementationOnce(async () => {
      h.monitor.stop();
      return { printerIp: "ip", state: "Idle", adf: "loaded" };
    });
    await h.monitor.tick();
    expect(h.scan).not.toHaveBeenCalled();
  });
  it("refuses a truncated journal instead of forgetting a potentially claimed batch", () => {
    const h = harness();
    fs.writeFileSync(h.journalPath, '{"phase":"claimed"');
    expect(() => createFeederMonitor(h)).toThrow("Incomplete feeder journal");
  });
});
