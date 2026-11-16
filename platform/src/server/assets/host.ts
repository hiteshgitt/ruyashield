import { domainToASCII } from "node:url";
import { AppError } from "../errors";
import { isIpLiteral } from "../net/ip";
import { EgressError, resolvePublic, type EgressDeps } from "../net/egress";

const RESERVED_SUFFIXES = [
  "local", "localhost", "test", "example", "invalid", "internal", "onion", "home.arpa", "lan", "corp", "arpa", "localdomain",
];

const invalid = (msg: string) => new AppError(422, "invalid_target", msg);

/**
 * RS-ASSET-001: turns user input ("https://Shop.Example.com/path") into a canonical public hostname.
 * Rejects IP literals, single-label names and reserved/internal suffixes. Pure; no network.
 */
export function parseHost(input: string): string {
  let s = (input ?? "").trim().toLowerCase();
  if (!s) throw invalid("Enter a domain name.");
  if (s.length > 300) throw invalid("That domain name is too long.");
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  if (s.includes("@")) throw invalid("Enter only the domain name, without credentials.");
  s = s.split(/[/?#]/)[0];
  if (/^\[.*\]/.test(s) || isIpLiteral(s)) throw invalid("IP addresses cannot be added; add the domain name instead.");
  if (/:\d*$/.test(s)) throw invalid("Enter the domain without a port.");
  s = s.replace(/\.$/, "");
  const ascii = domainToASCII(s);
  if (!ascii) throw invalid("That is not a valid domain name.");
  if (isIpLiteral(ascii)) throw invalid("IP addresses cannot be added; add the domain name instead.");
  if (ascii.length > 253) throw invalid("That domain name is too long.");
  const labels = ascii.split(".");
  if (labels.length < 2) throw invalid("Enter a fully qualified domain, such as shop.example.com.");
  for (const l of labels) {
    if (!/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(l)) throw invalid("That is not a valid domain name.");
  }
  if (/^\d+$/.test(labels[labels.length - 1])) throw invalid("That is not a valid domain name.");
  if (RESERVED_SUFFIXES.some((r) => ascii === r || ascii.endsWith(`.${r}`))) {
    throw invalid("Internal or reserved domain names cannot be added.");
  }
  return ascii;
}

/** Rejects names that currently resolve to private/reserved addresses. An unresolvable name is allowed (it may be pre-launch). */
export async function assertNotPrivate(host: string, deps: EgressDeps = {}): Promise<void> {
  try {
    await resolvePublic(host, deps);
  } catch (e) {
    if (e instanceof EgressError && e.code === "egress_blocked") throw invalid("That domain resolves to a private or reserved network address.");
  }
}
