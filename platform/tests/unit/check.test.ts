import { describe, expect, it } from "vitest";
import { metaContents, runCheck, TOKEN_PREFIX } from "@/server/assets/check";

const token = `${TOKEN_PREFIX}abc123`;
const txt = (byResolver: Record<string, string[] | Error>) => ({
  resolvers: Object.keys(byResolver).map((k) => [k]),
  resolveTxt: async (_name: string, [s]: string[]) => {
    const v = byResolver[s];
    if (v instanceof Error) throw v;
    return v.map((r) => [r]);
  },
});
const err = (code: string) => Object.assign(new Error(code), { code });

describe("runCheck dns_txt", () => {
  it("passes only when every resolver sees the token", async () => {
    expect((await runCheck("dns_txt", "acme.com", token, { txt: txt({ a: [token], b: ["x", token] }) })).status).toBe("passed");
  });
  it("fails when resolvers disagree", async () => {
    expect(await runCheck("dns_txt", "acme.com", token, { txt: txt({ a: [token], b: [] }) })).toMatchObject({ status: "failed", reason: "resolver_disagreement" });
  });
  it("fails when the token is absent or only a prefix matches", async () => {
    expect((await runCheck("dns_txt", "acme.com", token, { txt: txt({ a: [`${token}x`], b: [] }) })).status).toBe("failed");
    expect((await runCheck("dns_txt", "acme.com", token, { txt: txt({ a: err("ENOTFOUND"), b: err("ENODATA") }) })).reason).toBe("token_not_found");
  });
  it("is inconclusive (error, never passed) when a resolver fails", async () => {
    expect(await runCheck("dns_txt", "acme.com", token, { txt: txt({ a: [token], b: err("ETIMEOUT") }) })).toMatchObject({ status: "error", reason: "resolver_error" });
    expect((await runCheck("dns_txt", "acme.com", token, { txt: { resolvers: [] } })).status).toBe("error");
  });
});

describe("runCheck http", () => {
  const privateHost = { egress: { resolve: async () => [{ address: "10.0.0.1", family: 4 as const }] } };
  it("refuses hosts that resolve privately, and reports failed rather than passed", async () => {
    expect(await runCheck("http_file", "acme.com", token, privateHost)).toMatchObject({ status: "failed", reason: "egress_blocked" });
  });
  it("treats DNS failure as inconclusive", async () => {
    const r = await runCheck("meta_tag", "acme.com", token, { egress: { resolve: async () => { throw new Error("x"); } } });
    expect(r).toMatchObject({ status: "error", reason: "dns_failed" });
  });
});

describe("metaContents", () => {
  it("extracts content from matching tags in any attribute order and quoting", () => {
    const html = `<head><META content='${token}' NAME="ruyashield-verification"><meta name=ruyashield-verification content=other>
      <meta name="description" content="${token}"></head>`;
    expect(metaContents(html, "ruyashield-verification")).toEqual([token, "other"]);
  });
  it("ignores tokens in body text and comments that are not meta tags", () => {
    expect(metaContents(`<p>${token}</p><script>document.write('x')</script>`, "ruyashield-verification")).toEqual([]);
  });
});
