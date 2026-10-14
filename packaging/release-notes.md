SIEM на C++: собирает логи с серверов, находит атаки, объединяет их в инциденты, блокирует атакующие адреса и присылает уведомления. Весь код свой, включая хранилище событий; панель — на React.

## Приложение для Mac

**`SentinelCore-@VERSION@-macOS.dmg`** — одно приложение и для Apple Silicon (M1–M4), и для Intel; macOS 12 и новее.

1. Откройте `.dmg` и перетащите **SentinelCore** в «Программы».
2. Запустите. Приложение не подписано платным сертификатом Apple, поэтому первый раз macOS его остановит:
   - **macOS 15 и новее:** «Готово» → Системные настройки → Конфиденциальность и безопасность → «Всё равно открыть»;
   - **macOS 12–14:** правый щелчок по приложению → «Открыть» → «Открыть»;
   - или в Терминале: `xattr -dr com.apple.quarantine /Applications/SentinelCore.app`
3. Вверху справа появится значок щита, а панель откроется в браузере уже под администратором.

В меню значка: «Открыть панель», «Скопировать ключ администратора», «Перезапустить сервер», «Настройки», «Папка с данными», «Журнал сервера», «Выход». Данные лежат в `~/Library/Application Support/SentinelCore`. Сервер работает, пока открыто приложение.

## Docker

Образ для `amd64` и `arm64` (в том числе Docker Desktop на Mac с M-процессором): `@IMAGE@:@VERSION@` (он же `:latest`).

Скачайте **`docker-compose.yml`** из этого релиза и выполните:

```bash
docker compose up -d
docker compose logs sentinel     # здесь будет ключ администратора
```

Откройте **http://localhost:8080** и войдите с этим ключом. Свой ключ можно задать заранее строкой `SENTINEL_ADMIN_KEY` в `docker-compose.yml`. Данные хранятся в томе `sentinel-data` и сохраняются при обновлении:

```bash
docker compose pull && docker compose up -d
```

Без compose — одной командой:

```bash
docker run -d --name sentinel -p 8080:8080 -v sentinel-data:/data @IMAGE@:@VERSION@
```

HTTPS для агентов с других серверов включается строкой `SENTINEL_TLS: "on"` (сертификат создаётся сам) и `SENTINEL_PUBLIC_URL` с внешним адресом.

## Подключить сервер для защиты

В панели: **Серверы → Подключить сервер**. Панель выдаст готовую команду для агента. `sentinel-agent` для macOS есть в архиве **`sentinel-@VERSION@-macos-universal.tar.gz`** и внутри приложения; для Linux его можно собрать из исходников (см. README) или взять из образа: `docker run --rm --entrypoint cat @IMAGE@:@VERSION@ /usr/local/bin/sentinel-agent > sentinel-agent`.

## Файлы

| Файл | Что это |
|---|---|
| `SentinelCore-@VERSION@-macOS.dmg` | приложение для Mac |
| `sentinel-@VERSION@-macos-universal.tar.gz` | `sentinel-server` и `sentinel-agent` для Mac (командная строка), правила, панель |
| `docker-compose.yml` | запуск в Docker одной командой |
