// Общие команды для установки агента (страница «Серверы» и мастер «Подключить сайт»).
import type { EnrollToken } from "./api";

export const REPO = "https://github.com/KishoHiga/SIEM";
export const RELEASES = REPO + "/releases";

export type AgentPlatform = "mac" | "linux";

export function detectPlatform(): AgentPlatform {
  return /Mac/i.test(navigator.userAgent) ? "mac" : "linux";
}

// Скачать агента в ~/sentinel-agent и проверить, что он запускается.
export function getAgentCommands(platform: AgentPlatform): string {
  return platform === "mac"
    ? "mkdir -p ~/sentinel-agent && cd ~/sentinel-agent\n" +
        // rm перед cp: macOS убивает программу, скопированную поверх старой (помнит подпись прежнего файла)
        "rm -f sentinel-agent && cp /Applications/SentinelCore.app/Contents/Resources/bin/sentinel-agent .\n" +
        "xattr -d com.apple.quarantine sentinel-agent 2>/dev/null; ./sentinel-agent version"
    : "mkdir -p ~/sentinel-agent && cd ~/sentinel-agent\n" +
        "rm -f sentinel-agent && docker run --rm --entrypoint cat ghcr.io/kishohiga/siem /usr/local/bin/sentinel-agent > sentinel-agent\n" +
        "chmod +x sentinel-agent && ./sentinel-agent version";
}

// Если в конфиге нет public_url и сервер слушает 0.0.0.0, подставляем адрес, по которому открыта панель.
const PLACEHOLDER = "<адрес-сервера>";

export function enrollInfo(token: EnrollToken) {
  const guessed = token.server.includes(PLACEHOLDER);
  const server = token.server.replace(PLACEHOLDER, window.location.hostname);
  const command = token.command.replace(PLACEHOLDER, window.location.hostname).replace(/^sentinel-agent /, "./sentinel-agent ");
  return { guessed, server, command, local: server.includes("127.0.0.1") || server.includes("localhost") };
}

// Путь для командной строки: ~/... -> "$HOME/...", пробелы и кавычки безопасны.
export function shellPath(p: string): string {
  const esc = (s: string) => s.replace(/[\\"$`]/g, (c) => "\\" + c);
  if (p === "~") return '"$HOME"';
  if (p.startsWith("~/")) return '"$HOME/' + esc(p.slice(2)) + '"';
  if (/^[A-Za-z0-9_./-]+$/.test(p)) return p;
  return '"' + esc(p) + '"';
}

// Имя сайта для SIEM по пути (как у 'sentinel-agent add'): ~/SupSearch/server/logs/access.log -> supsearch
const GENERIC_FILES = new Set(["access", "error", "app", "server", "output", "out", "log", "logs", "requests", "request",
  "combined", "access_log", "error_log", "web", "http", "production", "development", "laravel", "django", "flask",
  "apache_access"]);
const GENERIC_DIRS = new Set(["logs", "log", "server", "api", "backend", "frontend", "var", "tmp", "storage", "app", "src",
  "www", "html", "public", "current", "shared", "opt", "srv", "data", "runtime", "dist", "build", "wp-content", "httpd",
  "sentinel-logs", "~", "private", "applications", "homebrew", "local", "usr"]);

export function cleanLabel(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .slice(0, 60);
}

export function guessSiteName(path: string): string {
  const parts = path.split(/[\\/]+/).filter(Boolean);
  const file = parts.pop() ?? "";
  let stem = file.replace(/\.[^.]*$/, "").toLowerCase();
  if (stem.endsWith(".log")) stem = stem.slice(0, -4);
  if (stem && !GENERIC_FILES.has(stem) && !stem.includes("*") && cleanLabel(stem)) return cleanLabel(stem);
  for (let i = parts.length - 1, depth = 0; i >= 0 && depth < 4; i--, depth++) {
    const d = parts[i].toLowerCase();
    if (!GENERIC_DIRS.has(d) && cleanLabel(d)) return cleanLabel(d);
  }
  return cleanLabel(stem) || "site";
}
