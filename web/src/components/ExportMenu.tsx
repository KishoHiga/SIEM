// Кнопка «Выгрузить»: CSV, CSV для Excel (кириллица и «;» как ждёт русский Excel) или JSON.
// Файл скачивает сам браузер по ссылке (сессия панели — в cookie), панель ничего не держит в памяти.
import { useEffect, useRef, useState } from "react";
import { exportUrl, type ExportKind } from "../api";
import { Icon } from "./Icons";

const FORMATS: { f: string; label: string; hint: string }[] = [
  { f: "excel", label: "CSV для Excel", hint: "открывается в Excel двойным щелчком" },
  { f: "csv", label: "CSV", hint: "для таблиц и скриптов (UTF-8, запятые)" },
  { f: "json", label: "JSON", hint: "все поля, для программ" },
  { f: "ndjson", label: "NDJSON", hint: "по объекту в строке" },
];

export function ExportMenu({
  kind,
  params,
  note,
}: {
  kind: ExportKind;
  params: () => Record<string, string | number | undefined>;
  note?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open]);
  return (
    <div className="menu-wrap" ref={ref}>
      <button className="btn btn-sm" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <Icon name="download" size={14} /> Выгрузить
      </button>
      {open && (
        <div className="menu" role="menu">
          {FORMATS.map((x) => (
            <a
              key={x.f}
              role="menuitem"
              href={exportUrl(kind, { ...params(), format: x.f })}
              download
              onClick={() => setOpen(false)}
            >
              <b>{x.label}</b>
              <small>{x.hint}</small>
            </a>
          ))}
          <div className="menu-note">{note ?? "С текущими фильтрами, до 100 000 строк."}</div>
        </div>
      )}
    </div>
  );
}
