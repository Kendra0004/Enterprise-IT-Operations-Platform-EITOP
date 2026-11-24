/**
 * Phase 3.2.3 — Directory Insights screenshots.
 *
 * Captures the three new tabs (Insights, Health, Correlation Gaps) ×
 * {dark, light} at 1440×900 into docs/screenshots/. Requires the demo
 * seed (connection + sync runs + findings + reconciliations).
 *
 * Usage (stack must be running: http://localhost:8080):
 *   node scripts/screenshots-insights.mjs
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

const THEMES = ["dark", "light"];

const TABS = [
  { name: "directory-insights", tab: "insights", ready: "findings-summary" },
  { name: "directory-health", tab: "health", ready: "health-verdict" },
  { name: "directory-gaps", tab: "gaps", ready: "gap-never_reconciled" },
];

async function login(page) {
  await page.goto(`${BASE}/login`);
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL((url) => !url.pathname.startsWith("/login"), {
    timeout: 15000,
  });
}

async function main() {
  await mkdir(OUT, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
  });
  const page = await context.newPage();

  await login(page);
  console.log("logged in");

  let count = 0;
  for (const theme of THEMES) {
    // Set before each navigation; the app reads eitop.theme on mount.
    // (No addInitScript here — it would re-apply on every load and pin
    // the first theme.)
    await page.evaluate((t) => localStorage.setItem("eitop.theme", t), theme);
    for (const target of TABS) {
      await page.goto(`${BASE}/active-directory?tab=${target.tab}`, {
        waitUntil: "networkidle",
      });
      await page.getByTestId(target.ready).waitFor({ timeout: 20000 });
      const file = `${target.name}--${theme}--1440x900.png`;
      await page.screenshot({ path: path.join(OUT, file), fullPage: true });
      count += 1;
      console.log("captured", file);
    }
  }

  await browser.close();
  console.log(`done: ${count} screenshots`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
