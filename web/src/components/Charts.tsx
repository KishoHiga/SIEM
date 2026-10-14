// Свои графики на SVG: временная шкала событий/алертов, мини-график, кольцо, полосы.
import { useMemo, useState } from "react";
import { hm, num } from "../format";

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * p) return m * p;
  return 10 * p;
}

// График событий в минуту (область) + алерты (столбики снизу).
export function Timeline({ points }: { points: { t: string; events: number; alerts: number }[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 800,
    H = 220,
    padL = 44,
    padR = 12,
    padT = 12,
    padB = 26;
  const n = points.length;
  const maxE = niceMax(Math.max(0, ...points.map((p) => p.events)));
  const maxA = Math.max(1, ...points.map((p) => p.alerts));
  const x = (i: number) => padL + (n <= 1 ? 0 : (i * (W - padL - padR)) / (n - 1));
  const y = (v: number) => padT + (H - padT - padB) * (1 - v / maxE);

  const { line, area } = useMemo(() => {
    if (!n) return { line: "", area: "" };
    const pts = points.map((p, i) => `${x(i).toFixed(1)},${y(p.events).toFixed(1)}`);
    const l = "M" + pts.join("L");
    return { line: l, area: `${l}L${x(n - 1).toFixed(1)},${H - padB}L${x(0).toFixed(1)},${H - padB}Z` };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [points, maxE]);

  if (!n) return <div className="chart-empty">Нет данных</div>;
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => f * maxE);
  const labelEvery = Math.max(1, Math.ceil(n / 8));
  const barW = Math.max(2, ((W - padL - padR) / Math.max(1, n)) * 0.6);
  const h = hover !== null ? points[hover] : null;

  return (
    <div className="timeline">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        onMouseLeave={() => setHover(null)}
        onMouseMove={(e) => {
          const r = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          const px = ((e.clientX - r.left) / r.width) * W;
          const i = Math.round(((px - padL) / (W - padL - padR)) * (n - 1));
          setHover(i >= 0 && i < n ? i : null);
        }}
      >
        <defs>
          <linearGradient id="tl-fill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.35" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={padL} x2={W - padR} y1={y(t)} y2={y(t)} className="grid" />
            <text x={padL - 6} y={y(t) + 4} className="axis" textAnchor="end">
              {t >= 1000 ? `${Math.round(t / 100) / 10}k` : Math.round(t)}
            </text>
          </g>
        ))}
        <path d={area} fill="url(#tl-fill)" />
        <path d={line} fill="none" stroke="var(--accent)" strokeWidth={2} vectorEffect="non-scaling-stroke" />
        {points.map((p, i) =>
          p.alerts > 0 ? (
            <rect
              key={i}
              x={x(i) - barW / 2}
              width={barW}
              y={H - padB - (p.alerts / maxA) * 40}
              height={(p.alerts / maxA) * 40}
              className="alert-bar"
            />
          ) : null,
        )}
        {points.map((p, i) =>
          i % labelEvery === 0 ? (
            <text key={p.t} x={x(i)} y={H - 8} className="axis" textAnchor="middle">
              {hm(p.t)}
            </text>
          ) : null,
        )}
        {hover !== null && (
          <line x1={x(hover)} x2={x(hover)} y1={padT} y2={H - padB} className="cursor" />
        )}
      </svg>
      {h && (
        <div className="chart-tip" style={{ left: `${(x(hover!) / W) * 100}%` }}>
          <b>{hm(h.t)}</b>
          <span>событий: {num(h.events)}</span>
          <span className="tip-alerts">алертов: {num(h.alerts)}</span>
        </div>
      )}
    </div>
  );
}

// Мини-график (например, событий в секунду за последнюю минуту).
export function Sparkline({ values, height = 36 }: { values: number[]; height?: number }) {
  const W = 120;
  const max = Math.max(1, ...values);
  const n = values.length;
  if (n < 2) return null;
  const pts = values.map((v, i) => `${((i * W) / (n - 1)).toFixed(1)},${(height - 2 - (v / max) * (height - 4)).toFixed(1)}`);
  return (
    <svg className="sparkline" viewBox={`0 0 ${W} ${height}`} preserveAspectRatio="none">
      <path d={`M${pts.join("L")}L${W},${height}L0,${height}Z`} className="spark-fill" />
      <path d={`M${pts.join("L")}`} className="spark-line" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

// Кольцевая диаграмма.
export function Donut({
  parts,
  size = 140,
  center,
}: {
  parts: { label: string; value: number; color: string }[];
  size?: number;
  center?: string;
}) {
  const total = parts.reduce((s, p) => s + p.value, 0);
  const r = 52,
    c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <svg width={size} height={size} viewBox="0 0 140 140" className="donut">
      <circle cx={70} cy={70} r={r} className="donut-track" />
      {total > 0 &&
        parts.map((p) => {
          const len = (p.value / total) * c;
          const el = (
            <circle
              key={p.label}
              cx={70}
              cy={70}
              r={r}
              fill="none"
              stroke={p.color}
              strokeWidth={16}
              strokeDasharray={`${len} ${c - len}`}
              strokeDashoffset={-offset}
              transform="rotate(-90 70 70)"
            >
              <title>
                {p.label}: {p.value}
              </title>
            </circle>
          );
          offset += len;
          return el;
        })}
      <text x={70} y={68} textAnchor="middle" className="donut-value">
        {center ?? num(total)}
      </text>
      <text x={70} y={88} textAnchor="middle" className="donut-label">
        за 24 ч
      </text>
    </svg>
  );
}

// Горизонтальные полосы (топ IP, источники).
export function Bars({
  items,
  onClick,
  wide,
}: {
  items: { label: string; value: number; tag?: string; title?: string }[];
  onClick?: (label: string) => void;
  wide?: boolean;  // длинные подписи (названия правил)
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  if (!items.length) return <div className="chart-empty">Нет данных</div>;
  return (
    <ul className={wide ? "bars wide" : "bars"}>
      {items.map((i) => (
        <li key={i.label} className={onClick ? "clickable" : ""} onClick={() => onClick?.(i.label)}>
          <span className="bar-label" title={i.title ?? i.label}>
            {i.label || "—"}
            {i.tag && <span className="cc">{i.tag}</span>}
          </span>
          <span className="bar-track">
            <span className="bar-fill" style={{ width: `${(i.value / max) * 100}%` }} />
          </span>
          <span className="bar-value">{num(i.value)}</span>
        </li>
      ))}
    </ul>
  );
}
