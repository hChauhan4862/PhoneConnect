/// The shell document names the icons the browser and the installed app load. A rename or a
/// missing file is invisible until someone opens the page, so it is checked here.

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const publicDir = join(webRoot, "public");

const html = readFileSync(join(webRoot, "index.html"), "utf8");

/// Every root-relative href in the document, which Vite serves from `public/`.
function localAssetHrefs(): string[] {
  return [...html.matchAll(/(?:href|src)="\/([^"]+)"/g)].map((match) => match[1]);
}

describe("the shell document's assets", () => {
  it("references at least the icons this project ships", () => {
    const hrefs = localAssetHrefs();
    expect(hrefs).toEqual(
      expect.arrayContaining([
        "favicon.ico",
        "favicon.svg",
        "apple-touch-icon.png",
        "site.webmanifest",
      ]),
    );
  });

  it("only names files that exist in public/", () => {
    for (const href of localAssetHrefs()) {
      // `/src/main.tsx` is a Vite entry point, not a static file.
      if (href.startsWith("src/")) continue;
      expect(existsSync(join(publicDir, href)), `public/${href} is missing`).toBe(true);
    }
  });

  it("declares in the web manifest every icon it lists", () => {
    const manifest = JSON.parse(readFileSync(join(publicDir, "site.webmanifest"), "utf8")) as {
      icons: { src: string }[];
    };
    expect(manifest.icons.length).toBeGreaterThan(0);
    for (const icon of manifest.icons) {
      expect(existsSync(join(publicDir, icon.src)), `public${icon.src} is missing`).toBe(true);
    }
  });
});
