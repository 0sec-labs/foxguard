#!/usr/bin/env node

import { pathToFileURL } from "node:url";

const DEFAULT_ENDPOINT =
  "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery?api-version=7.2-preview.1";

export function marketplaceQuery(publisher, extension) {
  return {
    filters: [
      {
        criteria: [
          {
            filterType: 7,
            value: `${publisher}.${extension}`,
          },
        ],
      },
    ],
    // Include versions while omitting large asset payloads.
    flags: 103,
  };
}

export async function publishedVersions({
  publisher,
  extension,
  endpoint = DEFAULT_ENDPOINT,
  fetchFn = fetch,
}) {
  const response = await fetchFn(endpoint, {
    method: "POST",
    headers: {
      Accept: "application/json;api-version=7.2-preview.1;excludeUrls=true",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(marketplaceQuery(publisher, extension)),
  });

  if (!response.ok) {
    throw new Error(`Marketplace API returned HTTP ${response.status}`);
  }

  const payload = await response.json();
  const match = payload?.results?.[0]?.extensions?.find(
    (item) =>
      item.extensionName?.toLowerCase() === extension.toLowerCase() &&
      item.publisher?.publisherName?.toLowerCase() === publisher.toLowerCase(),
  );

  if (!match) {
    return [];
  }

  return [...new Set((match.versions ?? []).map((item) => item.version).filter(Boolean))];
}

export async function waitForMarketplaceVersion({
  publisher,
  extension,
  version,
  timeoutMs = 10 * 60 * 1000,
  intervalMs = 15 * 1000,
  endpoint = DEFAULT_ENDPOINT,
  fetchFn = fetch,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  now = Date.now,
  log = console.log,
}) {
  const deadline = now() + timeoutMs;
  let attempt = 0;
  let lastVersions = [];
  let lastError;

  do {
    attempt += 1;
    try {
      lastVersions = await publishedVersions({ publisher, extension, endpoint, fetchFn });
      lastError = undefined;
      if (lastVersions.includes(version)) {
        log(`Marketplace reports ${publisher}.${extension} ${version} (attempt ${attempt}).`);
        return;
      }
      log(
        `Waiting for ${publisher}.${extension} ${version}; currently visible: ${lastVersions.join(", ") || "none"}.`,
      );
    } catch (error) {
      lastError = error;
      log(`Marketplace query failed on attempt ${attempt}: ${error.message}`);
    }

    if (now() >= deadline) {
      break;
    }
    await sleep(Math.min(intervalMs, Math.max(0, deadline - now())));
  } while (now() <= deadline);

  const detail = lastError
    ? ` Last query error: ${lastError.message}.`
    : ` Visible versions: ${lastVersions.join(", ") || "none"}.`;
  throw new Error(
    `Timed out after ${timeoutMs}ms waiting for ${publisher}.${extension} ${version}.${detail}`,
  );
}

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

async function main() {
  await waitForMarketplaceVersion({
    publisher: process.env.VSCODE_MARKETPLACE_PUBLISHER ?? "peaktwilight",
    extension: process.env.VSCODE_MARKETPLACE_EXTENSION ?? "foxguard",
    version: required("VSCODE_MARKETPLACE_VERSION"),
    timeoutMs: Number(process.env.VSCODE_MARKETPLACE_TIMEOUT_MS ?? 10 * 60 * 1000),
    intervalMs: Number(process.env.VSCODE_MARKETPLACE_INTERVAL_MS ?? 15 * 1000),
    endpoint: process.env.VSCODE_MARKETPLACE_ENDPOINT ?? DEFAULT_ENDPOINT,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`::error::${error.message}`);
    process.exitCode = 1;
  });
}
