// Сборка панели. В режиме разработки (npm run dev) запросы /api и /ws/live
// пересылаются на запущенный sentinel-server (адрес — переменная SENTINEL_URL).
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const target = process.env.SENTINEL_URL ?? "https://127.0.0.1:8443";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target, changeOrigin: true, secure: false },
      "/health": { target, changeOrigin: true, secure: false },
      "/ws/live": {
        target,
        changeOrigin: true,
        secure: false,
        ws: true,
        // сервер пускает WebSocket только со "своей" страницы — представляемся его адресом
        configure: (proxy) => proxy.on("proxyReqWs", (req) => req.setHeader("origin", target)),
      },
    },
  },
  build: {
    outDir: "dist",
    assetsDir: "assets",
    sourcemap: false,
    chunkSizeWarningLimit: 600,
  },
});
