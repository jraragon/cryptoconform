// M2.5.x -- shared real Chromium (Playwright) browser + secure-context
// page, reused across every operation's Chromium wiring so only one
// browser instance is launched for the whole test run, not one per operation.

import { createServer, type Server } from 'node:http';
import { chromium, type Browser, type Page } from 'playwright';

let sharedBrowser: Browser | undefined;
let sharedPage: Page | undefined;
let sharedServer: Server | undefined;

// A secure context is required for crypto.subtle to exist at all --
// confirmed empirically in M2.5.1: about:blank is NOT secure in this
// Chromium build (crypto.subtle === undefined there), but http://localhost
// IS (window.isSecureContext === true). A tiny local server, not any
// external network dependency, is sufficient.
export async function getSharedChromiumPage(): Promise<Page> {
  if (sharedPage) return sharedPage;
  sharedServer = createServer((_req, res) => res.end('<html><body>M2.5</body></html>'));
  await new Promise<void>((resolve) => sharedServer!.listen(0, '127.0.0.1', resolve));
  const address = sharedServer.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  sharedBrowser = await chromium.launch();
  sharedPage = await sharedBrowser.newPage();
  await sharedPage.goto(`http://localhost:${port}/`);
  const isSecure = await sharedPage.evaluate(() => window.isSecureContext);
  if (!isSecure) throw new Error('Chromium page is not a secure context -- crypto.subtle would be unavailable');
  return sharedPage;
}

export async function closeSharedChromium(): Promise<void> {
  await sharedBrowser?.close();
  sharedServer?.close();
  sharedBrowser = undefined;
  sharedPage = undefined;
  sharedServer = undefined;
}
