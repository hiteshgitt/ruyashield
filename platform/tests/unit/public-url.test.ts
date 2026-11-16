import { afterEach, describe, expect, it } from "vitest";
import { publicRequestUrl, publicUrl } from "@/server/http/public-url";

const prev = process.env.APP_URL;
afterEach(() => { process.env.APP_URL = prev; });

describe("public URLs behind a proxy", () => {
  it("uses APP_URL's origin, never the internal listener", () => {
    process.env.APP_URL = "https://ruyashield.ruyalab.com";
    expect(publicUrl("/auth/error?code=x").toString()).toBe("https://ruyashield.ruyalab.com/auth/error?code=x");
    expect(publicRequestUrl(new URL("http://localhost:3200/auth/callback?code=a&state=b")).toString())
      .toBe("https://ruyashield.ruyalab.com/auth/callback?code=a&state=b");
  });
  it("leaves an identity provider's absolute URL unchanged", () => {
    process.env.APP_URL = "https://ruyashield.ruyalab.com";
    expect(publicUrl("https://idp.example.com/authorize?x=1").toString()).toBe("https://idp.example.com/authorize?x=1");
  });
});
