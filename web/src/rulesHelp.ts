// Шаблоны новых правил, справка по полям и перевод ошибок проверки на русский.

export const TEMPLATES: { key: string; title: string; text: string; about: string }[] = [
  {
    key: "match",
    title: "Одно событие",
    about: "Алерт на каждое подходящее событие: атака в адресе запроса, вход под root, опасная команда.",
    text: `id: MY-RULE-001
name: Доступ к служебной странице
description: Кто-то обращается к /admin или /phpmyadmin — частая цель сканеров.
severity: medium          # info | low | medium | high | critical
type: match               # алерт на каждое подходящее событие
tags: [web]
where:
  type: web               # только запросы к сайту
field: http.path          # где искать шаблоны
transform: [url_decode, lowercase]
patterns:
  - '^/(admin|phpmyadmin|pma)(/|$|\\?)'
message: 'Обращение к {http.path} с {src_ip}'
tests:
  match:
    - '203.0.113.5 - - [12/Oct/2026:10:00:00 +0000] "GET /phpMyAdmin/ HTTP/1.1" 404 0 "-" "curl/8.0"'
  no_match:
    - '203.0.113.5 - - [12/Oct/2026:10:00:00 +0000] "GET /administration-guide.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
`,
  },
  {
    key: "threshold",
    title: "Порог",
    about: "N событий за окно времени с одного адреса (или пользователя): перебор, сканирование, флуд.",
    text: `id: MY-THRESHOLD-001
name: Много запрещённых запросов с одного адреса
description: 20 и более ответов 403 за минуту — похоже на перебор или сканирование.
severity: medium
type: threshold
threshold: 20             # сколько событий
window: 60                # за сколько секунд
group_by: [src_ip]        # считать отдельно для каждого адреса
tags: [web, scan]
where:
  type: web
  http.status: 403
message: '{count} ответов 403 за {window} с для {src_ip}'
tests:
  match:
    - '203.0.113.5 - - [12/Oct/2026:10:00:00 +0000] "GET /secret{n} HTTP/1.1" 403 0 "-" "curl/8.0"'
  no_match:
    - '203.0.113.5 - - [12/Oct/2026:10:00:00 +0000] "GET /page{n} HTTP/1.1" 200 512 "-" "curl/8.0"'
`,
  },
  {
    key: "sequence",
    title: "Цепочка",
    about: "Шаги по порядку за ограниченное время: например, перебор паролей, а затем успешный вход.",
    text: `id: MY-CHAIN-001
name: Вход после перебора паролей
description: С адреса сначала подбирали пароль, а потом вошли — учётная запись, вероятно, взломана.
severity: critical
type: sequence
group_by: [src_ip]        # шаги должны быть с одного адреса
within: 1800              # все шаги — в пределах 30 минут
steps:
  - rule: AUTH-BRUTE-001  # шаг 1: сработало другое правило
  - where:                # шаг 2: событие с условиями
      type: auth
      outcome: success
message: 'Вход {user} с {src_ip} после перебора паролей'
`,
  },
];

export const OPERATORS: [string, string][] = [
  ["type: web", "поле равно значению"],
  ["action: [sudo, su]", "одно из значений"],
  ["user: {not: [root, admin]}", "не равно ни одному"],
  ["http.status: {gte: 500}", "число: gte ≥, lte ≤, gt >, lt <"],
  ["http.path: {contains: wp-admin}", "содержит подстроку"],
  ["http.user_agent: {regex: 'sqlmap|nikto'}", "регулярное выражение"],
  ["user: {exists: true}", "поле заполнено (false — пустое)"],
];

export const TRANSFORMS: [string, string][] = [
  ["url_decode", "%3C → <"],
  ["html_decode", "&lt; → <"],
  ["unescape", "\\x3c, \\u003c → <"],
  ["remove_sql_comments", "убрать /* … */ и -- в SQL"],
  ["compress_space", "несколько пробелов → один"],
  ["lowercase", "в нижний регистр"],
];

export const KEYS: [string, string][] = [
  ["id", "уникальный код правила, например WEB-ADMIN-001"],
  ["name / description", "название и описание для панели"],
  ["severity", "важность: info, low, medium, high, critical"],
  ["type", "match — каждое событие, threshold — порог, sequence — цепочка"],
  ["where", "условия на поля события (все должны выполняться)"],
  ["field / transform / patterns", "регулярные выражения по одному полю"],
  ["group_by", "по каким полям считать и подавлять повторы (по умолчанию src_ip)"],
  ["threshold / window / distinct", "для порога: сколько, за сколько секунд, считать разные значения поля"],
  ["steps / within", "для цепочки: шаги и время на все шаги"],
  ["cooldown", "не повторять алерт чаще, чем раз в N секунд"],
  ["message", "текст алерта, поля подставляются: {src_ip}, {user}, {count}…"],
  ["enabled", "false — правило выключено"],
  ["tests", "примеры строк: match — должно сработать, no_match — не должно"],
];

// Ошибки сервера — по-английски и коротко; переводим самые частые.
export function ruleErrorText(msg: string): string {
  const rules: [RegExp, string][] = [
    [/^rule not found$/, "Правило не найдено"],
    [/no rules in the text/, "В тексте нет ни одного правила"],
    [/duplicate rule id (\S+)/, "Правило с id $1 уже есть"],
    [/missing 'id'/, "Не указан id"],
    [/unknown key '([^']+)'/, "Неизвестный ключ «$1»"],
    [/bad regex '(.*)': (.*)$/, "Ошибка в регулярном выражении «$1»: $2"],
    [/step refers to unknown or disabled rule (\S+)/, "Цепочка ссылается на правило $1, которого нет или оно выключено"],
    [/step refers to unknown rule (\S+)/, "Цепочка ссылается на неизвестное правило $1"],
    [/threshold rule needs 'threshold' >= 1.*$/, "Для порога нужен threshold (1 или больше)"],
    [/threshold rule needs 'window'.*$/, "Для порога нужно окно window (в секундах)"],
    [/sequence rule needs 'steps'.*$/, "Для цепочки нужно 2 шага или больше (steps)"],
    [/bad severity.*$/, "Неверная важность: info, low, medium, high или critical"],
    [/bad type '([^']*)'.*$/, "Неверный тип «$1»: match, threshold или sequence"],
    [/unknown transform '([^']*)'.*$/, "Неизвестное преобразование «$1»"],
    [/field '([^']*)': unknown operator '([^']*)'.*$/, "Поле «$1»: неизвестное условие «$2»"],
    [/'where' must be a map.*$/, "where — это список условий «поле: значение»"],
    [/example in 'match' gives no alert: (.*)$/, "Пример из match не вызывает алерт: $1"],
    [/example in 'no_match' gives an alert: (.*)$/, "Пример из no_match вызывает алерт (а не должен): $1"],
    [/has several rules/, "В этом файле несколько правил — удалите правило в тексте файла"],
    [/cannot change 'enabled' automatically/, "Не получилось поменять enabled автоматически — измените в тексте"],
    [/rule file is too large/, "Текст слишком большой (больше 256 КБ)"],
    [/^line (\d+): (.*)$/, "Строка $1: $2"],
  ];
  let out = msg.replace(/^rule (\S+): /, "");
  for (const [re, text] of rules) {
    if (re.test(out)) {
      out = out.replace(re, text);
      break;
    }
  }
  return out;
}

// Номер строки из ошибки разбора YAML ("line 12: ...").
export function errorLineOf(msg: string | undefined | null): number | null {
  const m = msg?.match(/\bline (\d+)\b/);
  return m ? Number(m[1]) : null;
}
