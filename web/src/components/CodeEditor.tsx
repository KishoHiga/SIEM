// Свой небольшой редактор YAML: подсветка, номера строк, отметка строки с ошибкой,
// Tab / Shift+Tab — отступы, Enter — продолжает отступ, Ctrl/Cmd+S — сохранить.
// Под прозрачным textarea лежит подсвеченная копия текста (обычный приём без сторонних библиотек).
import { useCallback, useLayoutEffect, useRef, type KeyboardEvent, type ReactNode } from "react";

type Tok = { t: string; c?: string };

const SCALAR = /^(true|false|yes|no|null|~|-?\d+(\.\d+)?)$/i;

// Разбор одной строки YAML на куски для подсветки (только оформление — смысл проверяет сервер).
function tokenize(line: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  const ws = line.match(/^\s*/)![0];
  if (ws) out.push({ t: ws });
  i = ws.length;
  if (line.startsWith("#", i)) {
    out.push({ t: line.slice(i), c: "tk-com" });
    return out;
  }
  if (line.startsWith("- ", i) || line.slice(i) === "-") {
    out.push({ t: "-", c: "tk-punct" });
    i += 1;
    const sp = line.slice(i).match(/^\s*/)![0];
    if (sp) out.push({ t: sp });
    i += sp.length;
  }
  const key = line.slice(i).match(/^([A-Za-z_][\w.\-]*)(\s*:)(?=\s|$)/);
  if (key) {
    out.push({ t: key[1], c: "tk-key" });
    out.push({ t: key[2], c: "tk-punct" });
    i += key[0].length;
  }
  // значение: строки в кавычках, комментарий, скобки, числа и true/false
  let word = "";
  const flush = () => {
    if (!word) return;
    const m = word.match(/^(\s*)(.*?)(\s*)$/)!;
    if (m[1]) out.push({ t: m[1] });
    if (m[2]) out.push({ t: m[2], c: SCALAR.test(m[2]) ? "tk-num" : "tk-val" });
    if (m[3]) out.push({ t: m[3] });
    word = "";
  };
  while (i < line.length) {
    const ch = line[i];
    if (ch === "'" || ch === '"') {
      flush();
      let j = i + 1;
      while (j < line.length) {
        if (ch === "'" && line[j] === "'" && line[j + 1] === "'") {
          j += 2;
          continue;
        }
        if (ch === '"' && line[j] === "\\") {
          j += 2;
          continue;
        }
        if (line[j] === ch) break;
        j++;
      }
      out.push({ t: line.slice(i, j + 1), c: "tk-str" });
      i = j + 1;
      continue;
    }
    if (ch === "#" && (i === 0 || /\s/.test(line[i - 1]))) {
      flush();
      out.push({ t: line.slice(i), c: "tk-com" });
      return out;
    }
    if ("[]{},".includes(ch)) {
      flush();
      out.push({ t: ch, c: "tk-punct" });
      i++;
      continue;
    }
    word += ch;
    i++;
  }
  flush();
  return out;
}

export function CodeEditor({
  value,
  onChange,
  readOnly = false,
  errorLine,
  onSave,
  label = "Текст правила",
}: {
  value: string;
  onChange: (v: string) => void;
  readOnly?: boolean;
  errorLine?: number | null; // с 1
  onSave?: () => void;
  label?: string;
}) {
  const ta = useRef<HTMLTextAreaElement>(null);
  const pre = useRef<HTMLPreElement>(null);
  const gutter = useRef<HTMLDivElement>(null);
  const lines = value.split("\n");

  const sync = useCallback(() => {
    if (!ta.current) return;
    if (pre.current) {
      pre.current.scrollTop = ta.current.scrollTop;
      pre.current.scrollLeft = ta.current.scrollLeft;
    }
    if (gutter.current) gutter.current.scrollTop = ta.current.scrollTop;
  }, []);
  useLayoutEffect(sync, [value, sync]);

  // Вставка через execCommand сохраняет историю отмены (Ctrl+Z) в браузере
  const insert = (text: string, selStart?: number, selEnd?: number) => {
    const el = ta.current!;
    if (selStart !== undefined) el.setSelectionRange(selStart, selEnd ?? selStart);
    if (!document.execCommand("insertText", false, text)) {
      const s = el.selectionStart,
        e = el.selectionEnd;
      el.setRangeText(text, s, e, "end");
      onChange(el.value);
    }
  };

  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    const el = e.currentTarget;
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
      e.preventDefault();
      onSave?.();
      return;
    }
    if (readOnly) return;
    const { selectionStart: s, selectionEnd: end, value: v } = el;
    if (e.key === "Tab") {
      e.preventDefault();
      const lineStart = v.lastIndexOf("\n", s - 1) + 1;
      if (s === end && !e.shiftKey) {
        insert("  ");
        return;
      }
      // отступ для всех выделенных строк
      const block = v.slice(lineStart, end);
      const changed = e.shiftKey
        ? block.replace(/(^|\n) {1,2}/g, "$1")
        : block.replace(/(^|\n)/g, "$1  ");
      insert(changed, lineStart, end);
      el.setSelectionRange(lineStart, lineStart + changed.length);
      return;
    }
    if (e.key === "Enter" && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      const lineStart = v.lastIndexOf("\n", s - 1) + 1;
      const cur = v.slice(lineStart, s);
      let ind = cur.match(/^\s*/)![0];
      if (/^\s*-\s/.test(cur) && !/:\s*$/.test(cur)) ind += "  ";
      if (/:\s*$/.test(cur)) ind += "  ";
      insert("\n" + ind);
    }
  };

  const gutterNodes: ReactNode[] = lines.map((_, i) => (
    <div key={i} className={errorLine === i + 1 ? "err" : undefined}>
      {i + 1}
    </div>
  ));

  return (
    <div className={`code-editor ${readOnly ? "ro" : ""}`}>
      <div className="code-gutter" ref={gutter} aria-hidden="true">
        {gutterNodes}
        <div>&nbsp;</div>
      </div>
      <div className="code-area">
        <pre ref={pre} aria-hidden="true">
          {lines.map((l, i) => (
            <div key={i} className={errorLine === i + 1 ? "code-line err" : "code-line"}>
              {tokenize(l).map((t, k) =>
                t.c ? (
                  <span key={k} className={t.c}>
                    {t.t}
                  </span>
                ) : (
                  t.t
                ),
              )}
            </div>
          ))}
          <div className="code-line" />
        </pre>
        <textarea
          ref={ta}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onScroll={sync}
          onKeyDown={onKey}
          readOnly={readOnly}
          spellCheck={false}
          autoCapitalize="off"
          autoComplete="off"
          autoCorrect="off"
          wrap="off"
          aria-label={label}
        />
      </div>
    </div>
  );
}
