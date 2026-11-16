import { isIP } from "node:net";
import { open, type AsnResponse, type CountryResponse, type Reader } from "maxmind";

/**
 * Local GeoIP lookups with MaxMind GeoLite2 databases (downloaded by scripts/geoip-update.mts with the customer's own
 * MaxMind licence). No IP ever leaves the server for geolocation. When a database is not configured the answer is
 * "unknown" (null), and the UI says so; it never guesses.
 *   GEOIP_COUNTRY_DB_PATH  GeoLite2-Country.mmdb (or GeoLite2-City.mmdb)
 *   GEOIP_ASN_DB_PATH      GeoLite2-ASN.mmdb
 */
export interface Geo { country: string | null; asn: number | null; asOrg: string | null }
export type GeoLookup = (ip: string) => Geo;
export const UNKNOWN: Geo = { country: null, asn: null, asOrg: null };

let cached: Promise<{ lookup: GeoLookup; country: boolean; asn: boolean }> | null = null;

async function load(): Promise<{ lookup: GeoLookup; country: boolean; asn: boolean }> {
  const cPath = process.env.GEOIP_COUNTRY_DB_PATH?.trim();
  const aPath = process.env.GEOIP_ASN_DB_PATH?.trim();
  let c: Reader<CountryResponse> | null = null, a: Reader<AsnResponse> | null = null;
  try { if (cPath) c = await open<CountryResponse>(cPath, { watchForUpdates: true, watchForUpdatesNonPersistent: true }); } catch { c = null; }
  try { if (aPath) a = await open<AsnResponse>(aPath, { watchForUpdates: true, watchForUpdatesNonPersistent: true }); } catch { a = null; }
  return { lookup: geoFrom(c, a), country: !!c, asn: !!a };
}

export function geoFrom(c: Pick<Reader<CountryResponse>, "get"> | null, a: Pick<Reader<AsnResponse>, "get"> | null): GeoLookup {
  return (ip) => {
    if (!isIP(ip)) return UNKNOWN;
    let country: string | null = null, asn: number | null = null, asOrg: string | null = null;
    try {
      const r = c?.get(ip);
      const iso = r?.country?.iso_code ?? r?.registered_country?.iso_code;
      if (iso && /^[A-Z]{2}$/.test(iso)) country = iso;
    } catch { /* unknown */ }
    try {
      const r = a?.get(ip);
      if (r && Number.isInteger(r.autonomous_system_number)) asn = r.autonomous_system_number;
      if (r?.autonomous_system_organization) asOrg = r.autonomous_system_organization.slice(0, 120);
    } catch { /* unknown */ }
    return { country, asn, asOrg };
  };
}

export async function geoip(): Promise<{ lookup: GeoLookup; country: boolean; asn: boolean }> {
  cached ??= load();
  return cached;
}
