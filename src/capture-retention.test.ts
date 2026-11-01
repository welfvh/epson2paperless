import { afterEach, describe, expect, it } from "vitest";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createGraph, decision, runScanSession, type SessionTransport } from "./scan-session.js";
import { buildIsPacket } from "./protocol.js";
import { finalizeSession } from "./output-tail.js";

class Transport extends EventEmitter implements SessionTransport {
  write(): boolean {
    return true;
  }
  end(): void {
    this.emit("close");
  }
  destroy(): void {
    this.emit("close");
  }
}

const roots: string[] = [];
function root(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scan-retention-"));
  roots.push(dir);
  return dir;
}
function files(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const name = path.join(dir, entry.name);
    return entry.isDirectory() ? files(name) : [name];
  });
}
afterEach(() => {
  for (const dir of roots.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("scan input retention", () => {
  it("retains the exact response before parsing rejects it", async () => {
    const dir = root();
    const transport = new Transport();
    const graph = createGraph<Record<string, never>>("WAIT", 1000)
      .state("WAIT", { on: {} })
      .build();
    const input = Buffer.from("malformed image response with original bytes");
    const pending = runScanSession({
      graph,
      initialCtx: {},
      transportFactory: () => Promise.resolve(transport),
      tempDir: dir,
      outputDir: dir,
      sessionTs: new Date(),
      action: "pdf",
    });
    setImmediate(() => transport.emit("data", input));
    expect((await pending).ok).toBe(false);
    expect(files(dir).some((file) => fs.readFileSync(file).equals(input))).toBe(true);
  });

  it("persists received bytes before the protocol handler runs", async () => {
    const dir = root();
    const transport = new Transport();
    const input = buildIsPacket(0xa000, Buffer.from("original page payload"));
    let persistedAtDispatch = false;
    const graph = createGraph<Record<string, never>>("WAIT", 1000)
      .state(
        "WAIT",
        decision(() => {
          persistedAtDispatch = files(dir).some((file) => fs.readFileSync(file).equals(input));
          return { next: "DONE" };
        }),
      )
      .build();
    const pending = runScanSession({
      graph,
      initialCtx: {},
      transportFactory: () => Promise.resolve(transport),
      tempDir: dir,
      outputDir: dir,
      sessionTs: new Date(),
      action: "jpg",
      allowZeroPages: true,
    });
    setImmediate(() => transport.emit("data", input));
    expect((await pending).ok).toBe(true);
    expect(persistedAtDispatch).toBe(true);
  });

  it("keeps a completed page when the next page fails", async () => {
    const dir = root();
    const transport = new Transport();
    const page = Buffer.from("original completed page");
    const graph = createGraph<Record<string, never>>("PAGE", 1000)
      .state("PAGE", {
        on: {
          0xa000: {
            next: "NEXT",
            flushPage: {
              side: "front",
              encode: () => Promise.resolve(page),
            },
          },
        },
      })
      .state("NEXT", {
        onEnter: () => {
          setImmediate(() => transport.emit("error", new Error("connection lost")));
          return null;
        },
        on: {},
      })
      .build();
    const pending = runScanSession({
      graph,
      initialCtx: {},
      transportFactory: () => Promise.resolve(transport),
      tempDir: dir,
      outputDir: dir,
      sessionTs: new Date(),
      action: "pdf",
    });
    setImmediate(() => transport.emit("data", buildIsPacket(0xa000, Buffer.alloc(0))));
    expect((await pending).ok).toBe(false);
    expect(files(dir).some((file) => fs.readFileSync(file).equals(page))).toBe(true);
  });

  it("keeps the source page when final output cannot be written", async () => {
    const dir = root();
    const temp = path.join(dir, "pages");
    fs.mkdirSync(temp);
    const page = Buffer.from("original page");
    fs.writeFileSync(path.join(temp, "page_001.jpg"), page);
    const blocked = path.join(dir, "not-a-directory");
    fs.writeFileSync(blocked, "existing file");
    await expect(
      finalizeSession({
        sessionTempDir: temp,
        outputDir: blocked,
        sessionTs: new Date(),
        action: "jpg",
        backPageIndices: [],
        paperless: undefined,
      }),
    ).rejects.toThrow();
    expect(fs.readFileSync(path.join(temp, "page_001.jpg"))).toEqual(page);
  });
});
