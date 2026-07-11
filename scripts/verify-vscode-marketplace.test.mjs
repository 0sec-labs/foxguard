import assert from "node:assert/strict";
import test from "node:test";

import {
  marketplaceQuery,
  publishedVersions,
  waitForMarketplaceVersion,
} from "./verify-vscode-marketplace.mjs";

function response(payload, { ok = true, status = 200 } = {}) {
  return { ok, status, json: async () => payload };
}

function listing(...versions) {
  return {
    results: [
      {
        extensions: [
          {
            extensionName: "foxguard",
            publisher: { publisherName: "PeakTwilight" },
            versions: versions.map((version) => ({ version })),
          },
        ],
      },
    ],
  };
}

test("queries the fully qualified extension name", () => {
  assert.equal(
    marketplaceQuery("peaktwilight", "foxguard").filters[0].criteria[0].value,
    "peaktwilight.foxguard",
  );
});

test("returns versions from the matching listing", async () => {
  const versions = await publishedVersions({
    publisher: "peaktwilight",
    extension: "foxguard",
    fetchFn: async () => response(listing("0.11.0", "0.10.0")),
  });
  assert.deepEqual(versions, ["0.11.0", "0.10.0"]);
});

test("polls until propagation completes", async () => {
  let query = 0;
  let clock = 0;
  await waitForMarketplaceVersion({
    publisher: "peaktwilight",
    extension: "foxguard",
    version: "0.11.0",
    timeoutMs: 100,
    intervalMs: 10,
    fetchFn: async () => response(listing(++query === 1 ? "0.10.0" : "0.11.0")),
    sleep: async (milliseconds) => {
      clock += milliseconds;
    },
    now: () => clock,
    log: () => {},
  });
  assert.equal(query, 2);
});

test("fails clearly when the requested version never appears", async () => {
  let clock = 0;
  await assert.rejects(
    waitForMarketplaceVersion({
      publisher: "peaktwilight",
      extension: "foxguard",
      version: "0.11.0",
      timeoutMs: 20,
      intervalMs: 10,
      fetchFn: async () => response(listing("0.10.0")),
      sleep: async (milliseconds) => {
        clock += milliseconds;
      },
      now: () => clock,
      log: () => {},
    }),
    /Timed out.*Visible versions: 0\.10\.0/,
  );
});

test("reports Marketplace API failures", async () => {
  await assert.rejects(
    publishedVersions({
      publisher: "peaktwilight",
      extension: "foxguard",
      fetchFn: async () => response({}, { ok: false, status: 503 }),
    }),
    /HTTP 503/,
  );
});
