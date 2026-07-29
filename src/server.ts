import process from "node:process";
import { dirname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { start, installGracefulShutdown, type StartResult } from "@red-cup-engineering/http-server";
import { buildApp, markdownDirectoryReader, watchContent } from "@red-cup-engineering/organizing-with-the-semantic-web/semantic-site-server";
import type { FSWatcher } from "node:fs";
import { fiveSixOneTheme } from "@red-cup-engineering/561-group-website-theme";

const CONTENT_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "content");
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 18_788;
const PUBLIC_CONTENT_SOURCE = "https://github.com/561-group/561-group-site/blob/main/content";

export function publicContentCitation(root: string, path: string): string {
  return `${PUBLIC_CONTENT_SOURCE}/${relative(root, path).replaceAll("\\", "/")}`;
}

export function create561GroupReader() {
  return markdownDirectoryReader({ citationFor: publicContentCitation });
}

export const SITE_CONFIG = {
  root: CONTENT_ROOT,
  baseUrl: "https://561.group",
  title: "The 561 Group",
  tagline: "An autonomous confederacy endeavoring in pursuit of Black Liberation, Indigenous Sovereignty, and long-horizon prosperity.",
  language: "en",
  publishedOnly: true,
  theme: fiveSixOneTheme,
  themeContext: { siteName: "The 561 Group", year: 2026 },
  webmentionPath: null,
  pingbackUrl: null,
} as const;

export type Serve561GroupSiteOptions = Readonly<{
  host?: string;
  port?: number;
  log?: (line: string) => void;
}>;

export type Serve561GroupSiteResult = StartResult & Readonly<{
  host: string;
  watcher: FSWatcher | null;
}>;

export function serve561GroupSiteOptionsFromEnv(): Required<Omit<Serve561GroupSiteOptions, "log">> {
  return {
    host: process.env.SITE_561_GROUP_HOST ?? process.env.HOST ?? DEFAULT_HOST,
    port: envPort() ?? DEFAULT_PORT,
  };
}

export async function serve561GroupSite(options: Serve561GroupSiteOptions = {}): Promise<Serve561GroupSiteResult> {
  const envOptions = serve561GroupSiteOptionsFromEnv();
  const host = options.host ?? envOptions.host;
  const port = options.port ?? envOptions.port;

  const reader = create561GroupReader();
  const app = buildApp(reader, SITE_CONFIG);
  const running = await start(app, { host, port });
  const watcher = watchContent(CONTENT_ROOT, reader, {});

  installGracefulShutdown(running, {
    onClosed: () => {
      watcher?.close();
      options.log?.("561 Group site stopped");
    },
    onError: (error) => options.log?.(`561 Group site shutdown failed: ${error instanceof Error ? error.message : String(error)}`),
  });

  options.log?.(`561 Group site listening at https://561.group/ on ${host}:${running.port}`);
  return { ...running, host, watcher };
}

function envPort(): number | undefined {
  const raw = process.env.SITE_561_GROUP_PORT ?? process.env.PORT;
  if (raw === undefined) return undefined;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > 65_535) {
    throw new Error(`Invalid SITE_561_GROUP_PORT: ${raw}`);
  }
  return parsed;
}

function isMain(): boolean {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMain()) {
  serve561GroupSite({ log: (line) => console.log(line) }).catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  });
}
