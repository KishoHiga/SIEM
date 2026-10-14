# Как подключить свой сайт к SentinelCore

SIEM узнаёт об атаках на сайт из **журнала запросов** (access log): одна строка — один запрос
(кто, когда, какой адрес, с каким ответом). Агент на компьютере с сайтом читает этот файл и присылает
новые строки в SIEM, а правила ищут в них перебор паролей, SQL-инъекции, XSS, сканеры и т.д.

Проще всего — **мастер в панели**: «Серверы» → **«Подключить сайт»**. Он задаст три вопроса, покажет
нужный код и готовые команды, а потом сам дождётся первой строки. Ниже — то же самое текстом.

## 1. Включить журнал запросов

Все варианты ниже пишут файл в формате nginx **combined** — его SIEM понимает лучше всего:

```
1.2.3.4 - - [14/Oct/2026:23:40:00 +0300] "POST /login HTTP/1.1" 401 20 "-" "Mozilla/5.0"
```

### nginx

Журнал уже ведётся: Linux — `/var/log/nginx/access.log`, Mac (Homebrew) — `/opt/homebrew/var/log/nginx/access.log`
(на Intel — `/usr/local/var/log/nginx/access.log`). Агент находит его сам. Если в nginx задан свой `log_format`,
верните стандартный: `access_log /var/log/nginx/access.log combined;`

### Apache

Журнал уже ведётся: Ubuntu/Debian — `/var/log/apache2/access.log`, CentOS/RHEL — `/var/log/httpd/access_log`,
Mac — `/private/var/log/apache2/access_log`, MAMP — `/Applications/MAMP/logs/apache_access.log`.
Формат должен быть `combined` (так по умолчанию в Ubuntu/Debian).

### Node.js (Express)

```bash
npm install morgan
```
В главном файле сервера сразу после `const app = express()`:
```js
const fs = require("fs");
const morgan = require("morgan");

fs.mkdirSync("logs", { recursive: true });
app.use(morgan("combined", { stream: fs.createWriteStream("logs/access.log", { flags: "a" }) }));
```
С `import` (ESM, TypeScript):
```ts
import fs from "fs";
import morgan from "morgan";

fs.mkdirSync("logs", { recursive: true });
app.use(morgan("combined", { stream: fs.createWriteStream("logs/access.log", { flags: "a" }) }));
```
Журнал: `logs/access.log` в папке, откуда запускается сайт. За nginx/прокси добавьте `app.set("trust proxy", 1)`.

### Python (Flask)

Ниже строки `app = Flask(__name__)`:
```python
import os, time
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
    return resp
```
Через gunicorn можно без кода: `gunicorn --access-logfile logs/access.log app:app`.

### Python (Django)

Файл `myproject/access_log.py` (рядом с `settings.py`):
```python
import os, time
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
        return response
```
В `settings.py` — в конец `MIDDLEWARE`:
```python
MIDDLEWARE = [
    # ... что уже было ...
    "myproject.access_log.AccessLogMiddleware",
]
```
Через gunicorn можно без кода: `gunicorn --access-logfile logs/access.log myproject.wsgi`.

### PHP

Если сайт работает через Apache или nginx — журнал уже есть (см. выше). Иначе (например, `php -S`) создайте
`sentinel-access-log.php` в корне сайта:
```php
<?php
// Журнал запросов для SentinelCore SIEM (формат nginx "combined").
register_shutdown_function(function () {
    $dir = __DIR__ . '/logs';
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
});
```
и подключите первой строкой в `index.php`: `<?php require __DIR__ . '/sentinel-access-log.php'; ?>`
(или для всего сайта — `auto_prepend_file = /полный/путь/sentinel-access-log.php` в `.user.ini`).

### WordPress

Свой сервер с nginx/Apache — берите их журнал. Если хостинг журнал не даёт — плагин
`wp-content/mu-plugins/sentinel-access-log.php` (включается сам):
```php
<?php
// Журнал запросов для SentinelCore SIEM (формат nginx "combined").
register_shutdown_function(function () {
    $dir = WP_CONTENT_DIR . '/sentinel-logs';
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
});
```
Журнал: `wp-content/sentinel-logs/access.log` (закрыт от просмотра из браузера).

### Сайт в Docker

Журнал пишется внутрь контейнера — подключите его папку к компьютеру, например в `docker-compose.yml`:
```yaml
    volumes:
      - ./logs:/app/logs
```
и укажите агенту путь на компьютере (`./logs/access.log` рядом с `docker-compose.yml`).

## 2. Агент

```bash
mkdir -p ~/sentinel-agent && cd ~/sentinel-agent
# Mac: агент лежит внутри приложения
rm -f sentinel-agent && cp /Applications/SentinelCore.app/Contents/Resources/bin/sentinel-agent .
# подключить к SIEM (команду с токеном выдаёт панель: «Серверы» → «Подключить сервер»)
./sentinel-agent enroll --server http://127.0.0.1:8080 --token sne_...
# читать журнал сайта (формат агент определит сам)
./sentinel-agent add ~/my-site/logs/access.log --name my-site
# работать в фоне и запускаться самому после перезагрузки
./sentinel-agent service install
```

| Команда | Что делает |
|---|---|
| `add ФАЙЛ [--name ИМЯ] [--format nginx\|json\|syslog\|kv] [--from-beginning]` | добавляет файл в `agent.yaml`, показывает, как поняты последние строки; работающий агент подхватит файл за пару секунд |
| `remove ФАЙЛ` | перестать читать файл |
| `sources` | что агент читает сейчас и работает ли служба |
| `service install` | фоновая служба: на Mac — launchd (журнал агента: `~/Library/Logs/SentinelCore/agent.log`), на Linux — systemd (`sudo`, журнал: `journalctl -u sentinel-agent`), на Windows — служба `SentinelAgent` |
| `service status` / `service uninstall` | состояние / убрать службу |

По умолчанию отправляются только **новые** строки (`--from-beginning` — весь файл). Два агента с одними
настройками не запустятся: если агент уже работает в окне Терминала, остановите его (`Ctrl+C`) перед `service install`.

**Mac:** если сайт лежит в «Документах», «Рабочем столе» или «Загрузках», macOS не даст фоновому агенту читать
файл. Дайте `~/sentinel-agent/sentinel-agent` «Доступ к диску» (Системные настройки → Конфиденциальность и
безопасность → Доступ к диску) или перенесите проект, например, в `~/Projects`.

## 3. Проверка

Откройте сайт и пощёлкайте по страницам — строки появятся в «Живой ленте» на главной панели.
Если их нет:
1. `tail -n 3 ~/my-site/logs/access.log` — сайт пишет журнал?
2. `./sentinel-agent service status` — агент работает?
3. `./sentinel-agent sources` — файл в списке?
4. журнал агента (`~/Library/Logs/SentinelCore/agent.log` на Mac, `sudo journalctl -u sentinel-agent` на Linux).
