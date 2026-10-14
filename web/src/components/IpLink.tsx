// IP-адрес — ссылка на его карточку; рядом код страны (если известен) и отметка «в чёрном списке».
import type { MouseEvent } from "react";
import { countryName } from "../countries";
import { Link } from "../router";

export function IpLink({ ip, country, listed }: { ip?: string | null; country?: string | null; listed?: boolean }) {
  if (!ip) return <span className="muted">—</span>;
  const addr = ip.split("/")[0];
  return (
    <span className="ip-link">
      <Link to={`/ip/${encodeURIComponent(addr)}`} className="mono" onClick={(e: MouseEvent) => e.stopPropagation()}>
        {ip}
      </Link>
      {country && (
        <span className="cc" title={countryName(country)}>
          {country}
        </span>
      )}
      {listed && (
        <span className="cc cc-bad" title="Адрес в чёрном списке">
          ЧС
        </span>
      )}
    </span>
  );
}
