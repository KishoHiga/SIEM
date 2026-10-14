// Готовые инструкции: как включить журнал запросов в популярных фреймворках.
// Все варианты пишут строки в формате nginx "combined" — его понимают правила SIEM
// (перебор паролей, SQL-инъекции, сканеры и т.д.):
//   1.2.3.4 - user [14/Oct/2026:23:40:00 +0300] "POST /login HTTP/1.1" 401 20 "-" "Mozilla/5.0"
// Тот же текст лежит в docs/connect-site.md.

export type Platform = "mac" | "linux";

export interface GuideStep {
  text: string; // что сделать
  file?: string; // в какой файл (подпись над кодом)
  code?: string;
}

export interface SiteGuide {
  id: string;
  title: string;
  subtitle: string;
  // ready — журнал уже ведётся (nginx, Apache): нужно только указать путь
  kind: "ready" | "code" | "custom";
  // для kind=code: путь к журналу относительно папки проекта
  logInProject?: string;
  // для kind=ready: где обычно лежит журнал
  paths?: Record<Platform, string[]>;
  steps: GuideStep[];
  note?: string;
}

const EXPRESS_CJS = String.raw`const fs = require("fs");
const morgan = require("morgan");

fs.mkdirSync("logs", { recursive: true });
app.use(morgan("combined", { stream: fs.createWriteStream("logs/access.log", { flags: "a" }) }));`;

const EXPRESS_ESM = String.raw`import fs from "fs";
import morgan from "morgan";

fs.mkdirSync("logs", { recursive: true });
app.use(morgan("combined", { stream: fs.createWriteStream("logs/access.log", { flags: "a" }) }));`;

const FLASK = String.raw`import os, time
from urllib.parse import quote
from flask import request

os.makedirs("logs", exist_ok=True)
_access_log = open("logs/access.log", "a", buffering=1, encoding="utf-8")

def _q(s):
    return (s or "-").replace("\\", "\\x5C").replace('"', "\\x22")

@app.after_request
def write_access_log(resp):
    qs = request.query_string.decode("latin-1")
    path = quote(request.path) + ("?" + qs if qs else "")
    _access_log.write('%s - - [%s] "%s %s %s" %d %d "%s" "%s"\n' % (
        request.remote_addr or "-", time.strftime("%d/%b/%Y:%H:%M:%S %z"),
        request.method, _q(path), request.environ.get("SERVER_PROTOCOL", "HTTP/1.1"),
        resp.status_code, resp.content_length or 0,
        _q(request.referrer), _q(request.user_agent.string)))
    return resp`;

const DJANGO = String.raw`import os, time
from urllib.parse import quote

os.makedirs("logs", exist_ok=True)
_access_log = open("logs/access.log", "a", buffering=1, encoding="utf-8")

def _q(s):
    return (s or "-").replace("\\", "\\x5C").replace('"', "\\x22")

class AccessLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        user = getattr(request, "user", None)
        name = user.get_username() if user is not None and user.is_authenticated else ""
        qs = request.META.get("QUERY_STRING", "")
        path = quote(request.path) + ("?" + qs if qs else "")
        size = 0 if response.streaming else len(response.content)
        _access_log.write('%s - %s [%s] "%s %s %s" %d %d "%s" "%s"\n' % (
            request.META.get("REMOTE_ADDR", "-"), _q(name).replace(" ", "_"),
            time.strftime("%d/%b/%Y:%H:%M:%S %z"), request.method, _q(path),
            request.META.get("SERVER_PROTOCOL", "HTTP/1.1"), response.status_code, size,
            _q(request.META.get("HTTP_REFERER")), _q(request.META.get("HTTP_USER_AGENT"))))
        return response`;

const PHP_LOG = (dir: string) => String.raw`<?php
// Журнал запросов для SentinelCore SIEM (формат nginx "combined").
register_shutdown_function(function () {
    $dir = ${dir};
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
        @file_put_contents($dir . '/.htaccess', "Require all denied\n");  // не отдавать журнал в браузер
        @file_put_contents($dir . '/index.html', '');
    }
    $q = function ($s) {
        return ($s === null || $s === '') ? '-' : str_replace(['\\', '"'], ['\\x5C', '\\x22'], $s);
    };
    $line = sprintf("%s - - [%s] \"%s %s %s\" %d 0 \"%s\" \"%s\"\n",
        $_SERVER['REMOTE_ADDR'] ?? '-', date('d/M/Y:H:i:s O'),
        $_SERVER['REQUEST_METHOD'] ?? 'GET', $q($_SERVER['REQUEST_URI'] ?? '/'),
        $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1', http_response_code() ?: 200,
        $q($_SERVER['HTTP_REFERER'] ?? null), $q($_SERVER['HTTP_USER_AGENT'] ?? null));
    @file_put_contents($dir . '/access.log', $line, FILE_APPEND | LOCK_EX);
});`;

export const GUIDES: SiteGuide[] = [
  {
    id: "nginx",
    title: "nginx",
    subtitle: "сайт отдаёт nginx (часто вместе с PHP, Node.js, Python)",
    kind: "ready",
    paths: {
      linux: ["/var/log/nginx/access.log"],
      mac: ["/opt/homebrew/var/log/nginx/access.log", "/usr/local/var/log/nginx/access.log"],
    },
    steps: [
      {
        text: "Ничего включать не нужно: nginx сам ведёт журнал запросов. Агент находит его автоматически, но лучше указать путь явно — тогда в SIEM у сайта будет понятное имя.",
      },
    ],
    note: "Если в nginx свой формат журнала (log_format), верните стандартный: access_log /var/log/nginx/access.log combined;",
  },
  {
    id: "apache",
    title: "Apache",
    subtitle: "httpd / apache2, в том числе MAMP и XAMPP",
    kind: "ready",
    paths: {
      linux: ["/var/log/apache2/access.log", "/var/log/httpd/access_log"],
      mac: ["/private/var/log/apache2/access_log", "/Applications/MAMP/logs/apache_access.log", "/Applications/XAMPP/logs/access_log"],
    },
    steps: [
      {
        text: "Apache уже ведёт журнал запросов. Проверьте, что в настройках формат combined (так по умолчанию в Ubuntu/Debian): CustomLog ${APACHE_LOG_DIR}/access.log combined",
      },
    ],
  },
  {
    id: "express",
    title: "Node.js (Express)",
    subtitle: "app = express()",
    kind: "code",
    logInProject: "logs/access.log",
    steps: [
      { text: "В терминале, в папке проекта, поставьте маленькую библиотеку журнала:", code: "npm install morgan" },
      {
        text: "В главном файле сервера (обычно app.js, index.js или server.js) сразу после строки const app = express() вставьте:",
        file: "app.js / index.js (require)",
        code: EXPRESS_CJS,
      },
      { text: "Если в проекте import вместо require (или TypeScript) — тот же код так:", file: "index.ts / index.mjs (import)", code: EXPRESS_ESM },
      { text: "Перезапустите сайт и откройте пару страниц — в папке проекта появится logs/access.log." },
    ],
    note: "Если перед сайтом стоит nginx или другой прокси, добавьте app.set(\"trust proxy\", 1) — иначе в журнале будет адрес прокси, а не посетителя.",
  },
  {
    id: "flask",
    title: "Python (Flask)",
    subtitle: "app = Flask(__name__)",
    kind: "code",
    logInProject: "logs/access.log",
    steps: [
      { text: "В файле, где создаётся app = Flask(__name__), ниже этой строки вставьте:", file: "app.py", code: FLASK },
      { text: "Перезапустите сайт — в папке, откуда вы его запускаете, появится logs/access.log." },
      {
        text: "Запускаете через gunicorn? Тогда код не нужен — достаточно флага:",
        code: "gunicorn --access-logfile logs/access.log app:app",
      },
    ],
    note: "За nginx/прокси подключите werkzeug ProxyFix — иначе в журнале будет адрес прокси.",
  },
  {
    id: "django",
    title: "Python (Django)",
    subtitle: "manage.py, settings.py",
    kind: "code",
    logInProject: "logs/access.log",
    steps: [
      {
        text: "Создайте файл access_log.py рядом с settings.py (в папке с именем вашего проекта) и вставьте:",
        file: "<проект>/access_log.py",
        code: DJANGO,
      },
      {
        text: "В settings.py добавьте строку в конец списка MIDDLEWARE (замените myproject на имя папки проекта):",
        file: "settings.py",
        code: 'MIDDLEWARE = [\n    # ... что уже было ...\n    "myproject.access_log.AccessLogMiddleware",\n]',
      },
      { text: "Перезапустите сайт — рядом с manage.py появится logs/access.log." },
      { text: "Запускаете через gunicorn? Можно без кода:", code: "gunicorn --access-logfile logs/access.log myproject.wsgi" },
    ],
  },
  {
    id: "php",
    title: "PHP",
    subtitle: "свой сайт на PHP, Laravel, php -S",
    kind: "code",
    logInProject: "logs/access.log",
    steps: [
      {
        text: "Сайт работает через Apache или nginx? Тогда выберите их выше — журнал уже есть. Если нет (php -S, хостинг без доступа к журналам) — создайте в корне сайта файл:",
        file: "sentinel-access-log.php",
        code: PHP_LOG("__DIR__ . '/logs'"),
      },
      {
        text: "Подключите его первой строкой в index.php (или во всех входных файлах):",
        file: "index.php",
        code: "<?php require __DIR__ . '/sentinel-access-log.php'; ?>",
      },
      {
        text: "Или для всего сайта сразу — строкой в .user.ini (или php.ini) в корне сайта:",
        file: ".user.ini",
        code: "auto_prepend_file = /полный/путь/к/сайту/sentinel-access-log.php",
      },
    ],
    note: "Папка logs закрыта от просмотра из браузера файлом .htaccess (для Apache). Для nginx добавьте: location /logs/ { deny all; }",
  },
  {
    id: "wordpress",
    title: "WordPress",
    subtitle: "wp-login.php, wp-admin",
    kind: "code",
    logInProject: "wp-content/sentinel-logs/access.log",
    steps: [
      {
        text: "Если у вас свой сервер с nginx или Apache — выберите их выше, журнал уже есть. Если хостинг не даёт журнал — создайте файл-плагин (папку mu-plugins создайте, если её нет; такие плагины включаются сами):",
        file: "wp-content/mu-plugins/sentinel-access-log.php",
        code: PHP_LOG("WP_CONTENT_DIR . '/sentinel-logs'"),
      },
      { text: "Откройте любую страницу сайта — появится wp-content/sentinel-logs/access.log (закрыт от просмотра из браузера)." },
    ],
    note: "SIEM сразу будет ловить перебор паролей на wp-login.php и xmlrpc.php.",
  },
  {
    id: "other",
    title: "Другое / не знаю",
    subtitle: "у сайта уже есть файл журнала",
    kind: "custom",
    steps: [
      {
        text: "Укажите путь к файлу, куда сайт пишет журнал запросов. Лучше всего SIEM понимает формат nginx/Apache «combined» и JSON-строки с полями ip, method, path, status. Агент сам определит формат по последним строкам.",
      },
    ],
  },
];

export function guideById(id: string): SiteGuide | undefined {
  return GUIDES.find((g) => g.id === id);
}
