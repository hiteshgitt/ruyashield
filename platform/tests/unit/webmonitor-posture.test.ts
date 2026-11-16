import { describe, expect, it } from "vitest";
import { MAX_POSTURE_HOSTS, parseHostList } from "@/server/webmonitor/posture";

describe("parseHostList", () => {
  it("normalises, de-duplicates and drops empties", () => {
    expect(parseHostList(" Shop.Example.com, ,shop.example.com,api.example.com")).toEqual(["shop.example.com", "api.example.com"]);
    expect(parseHostList(null)).toEqual([]);
  });
  it("refuses invalid hosts and oversized lists", () => {
    expect(() => parseHostList("not a host!")).toThrow(expect.objectContaining({ code: "invalid_host" }));
    const many = Array.from({ length: MAX_POSTURE_HOSTS + 1 }, (_, i) => `h${i}.example.com`).join(",");
    expect(() => parseHostList(many)).toThrow(expect.objectContaining({ code: "too_many_hosts" }));
  });
});
