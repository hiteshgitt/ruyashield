import { describe, expect, it } from "vitest";
import { createWebMonitorFilesAdapter, fileFindings, type StoredFileReport } from "@/server/webmonitor/files";

const now = new Date("2026-11-20T03:00:00Z");
const report = (over: Partial<StoredFileReport> = {}): StoredFileReport => ({
  host: "shop.example.com", complete: true, observedAt: new Date("2026-11-20T02:00:00Z"),
  findings: [
    { id: "f1", path: "wp-content/uploads/2026/11/thumb.php", line: 1, rule: "php-in-uploads", severity: "critical", title: "PHP file in an uploads folder", snippet: "<?php" },
    { id: "f2", path: "wp-includes/version.php", line: 0, rule: "core-modified", severity: "high", title: "WordPress core file differs from the official release", snippet: "" },
  ],
  ...over,
});
const run = (r: StoredFileReport | null) => createWebMonitorFilesAdapter({ lookup: async () => r, now: () => now })
  .run({ host: "shop.example.com" } as never);

describe("webmonitor.files", () => {
  it("one finding per rule and file, with file and line in the location", () => {
    const f = fileFindings("shop.example.com", report());
    expect(f.map((x) => x.issueKey)).toEqual(["file.php-in-uploads.wp-content_uploads_2026_11_thumb.php", "file.core-modified.wp-includes_version.php"]);
    expect(f[0].location).toContain("line 1");
    expect(f[1].remediation).toMatch(/Re-install/);
  });
  it("no report is clean, a stale report is an error, a partial empty scan cannot close findings", async () => {
    expect(await run(null)).toMatchObject({ status: "ok", findings: [] });
    expect(await run(report({ observedAt: new Date("2026-11-10T00:00:00Z") }))).toMatchObject({ status: "error", reason: "webmonitor_report_stale" });
    expect(await run(report({ complete: false, findings: [] }))).toMatchObject({ status: "error", reason: "webmonitor_scan_in_progress" });
    expect((await run(report())).status).toBe("ok");
  });
});
