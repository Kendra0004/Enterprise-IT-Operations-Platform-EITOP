/**
 * Visual verification screenshots (Phase 2.8).
 *
 * Usage (stack must be running: http://localhost:8080):
 *   node scripts/screenshots.mjs
 *
 * Captures every page × {dark, light} × {1440×900, 1280×800, 768×1024,
 * 390×844} into docs/screenshots/. Login uses the real UI flow.
 */

import { chromium } from "playwright-core";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BASE = process.env.EITOP_URL ?? "http://localhost:8080";
const EMAIL = process.env.EITOP_EMAIL ?? "admin@example.com";
const PASSWORD = process.env.EITOP_PASSWORD ?? "Adm1n-Bootstrap!2026";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.resolve(ROOT, "../docs/screenshots");

const VIEWPORTS = [
  { name: "1440x900", width: 1440, height: 900 },
  { name: "1280x800", width: 1280, height: 800 },
  { name: "768x1024", width: 768, height: 1024 },
  { name: "390x844", width: 390, height: 844 },
];

const THEMES = ["dark", "light"];

async function login(page) {
  await page.goto(`${BASE}/login`);
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((url) => !url.pathname.startsWith("/login"), {
    timeout: 15000,
  });
}

async function firstEndpointId(page) {
  await page.goto(`${BASE}/endpoints`);
  await page.waitForSelector('a[href^="/endpoints/"]', { timeout: 15000 });
  const href = await page
    .locator('a[href^="/endpoints/"]')
    .first()
    .getAttribute("href");
  return href.split("/")[2];
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ viewport: VIEWPORTS[0] });
  const page = await context.newPage();

  await login(page);
  const endpointId = await firstEndpointId(page);
  console.log("logged in; endpoint:", endpointId);

  const pages = [
    { name: "login", path: "/login", anonymous: true },
    { name: "dashboard", path: "/" },
    { name: "endpoints", path: "/endpoints" },
    { name: "endpoint-detail", path: `/endpoints/${endpointId}` },
    { name: "endpoint-history", path: `/endpoints/${endpointId}/history` },
    { name: "groups", path: "/groups" },
    { name: "administration-preview", path: "/admin" },
  ];

  let count = 0;
  for (const theme of THEMES) {
    for (const vp of VIEWPORTS) {
      await page.setViewportSize({ width: vp.width, height: vp.height });
      for (const target of pages) {
        // Anonymous pages must not carry a session.
        if (target.anonymous) {
          const anon = await browser.newContext({
            viewport: { width: vp.width, height: vp.height },
            storageState: undefined,
          });
          await anon.addInitScript((t) => {
            localStorage.setItem("eitop.theme", t);
          }, theme);
          const ap = await anon.newPage();
          await ap.goto(`${BASE}${target.path}`, { waitUntil: "networkidle" });
          const file = `${target.name}--${theme}--${vp.name}.png`;
          await ap.screenshot({ path: path.join(OUT, file), fullPage: true });
          await anon.close();
          count++;
          continue;
        }

        await context.addInitScript((t) => {
          localStorage.setItem("eitop.theme", t);
        }, theme);
        await page.goto(`${BASE}${target.path}`, { waitUntil: "networkidle" });
        // Let React Query settle late-arriving section queries.
        await page.waitForTimeout(400);
        const file = `${target.name}--${theme}--${vp.name}.png`;
        await page.screenshot({ path: path.join(OUT, file), fullPage: true });
        count++;
        console.log("captured", file);
      }
    }
  }

  // Extra: mobile navigation drawer open (390×844, dark) — fresh context
  // so the capture is independent of prior navigations.
  const drawerCtx = await browser.newContext({
    viewport: { width: 390, height: 844 },
  });
  await drawerCtx.addInitScript(() => localStorage.setItem("eitop.theme", "dark"));
  const dp = await drawerCtx.newPage();
  await login(dp);
  await dp.goto(`${BASE}/endpoints`, { waitUntil: "networkidle" });
  await dp.getByRole("button", { name: "Open navigation menu" }).click();
  await dp.waitForTimeout(300);
  await dp.screenshot({ path: path.join(OUT, "mobile-drawer--dark--390x844.png") });
  count++;
  await drawerCtx.close();

  await browser.close();
  console.log(`done: ${count} screenshots → ${OUT}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
