import { defineConfig } from "vite";
import { crx } from "@crxjs/vite-plugin";
import manifest from "./manifest.json" assert { type: "json" };
import { resolve } from "node:path";

export default defineConfig({
  plugins: [crx({ manifest })],
  build: {
    rollupOptions: {
      input: {
        // confirm popup is not referenced from the manifest (we open it
        // via chrome.windows.create); it must be listed here so vite
        // bundles it and produces a usable .js.
        confirm: resolve(__dirname, "src/confirm/confirm.html"),
        // connect page is opened from the popup via chrome.tabs.create;
        // same reason: declared as an entry so vite bundles it as a
        // self-contained HTML.
        connect: resolve(__dirname, "src/connect/connect.html"),
        // offscreen document that hosts navigator.serial (not available
        // in MV3 SW). Loaded from the SW via chrome.offscreen.createDocument.
        offscreen: resolve(__dirname, "src/offscreen/serial.html"),
        // settings page (user-customisable RPCs). Referenced from
        // manifest.options_ui; vite needs the explicit entry so the
        // page is bundled as standalone HTML.
        options: resolve(__dirname, "src/options/options.html"),
      },
    },
  },
  resolve: {
    alias: {
      "@": new URL("./src", import.meta.url).pathname,
    },
  },
});
