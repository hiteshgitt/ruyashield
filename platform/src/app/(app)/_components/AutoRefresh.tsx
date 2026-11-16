"use client";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

/**
 * Re-renders the server page every few seconds while a run is active, and stops once the page renders it as finished
 * (the parent stops rendering this component). Paused while the tab is hidden. The status line is announced politely.
 */
export function AutoRefresh({ everyMs = 5000, label = "Updating automatically while the run is in progress." }: { everyMs?: number; label?: string }) {
  const router = useRouter();
  const [at, setAt] = useState<string | null>(null);
  useEffect(() => {
    const tick = () => {
      if (document.visibilityState !== "visible") return;
      router.refresh();
      setAt(new Date().toLocaleTimeString());
    };
    const t = setInterval(tick, Math.max(2000, everyMs));
    document.addEventListener("visibilitychange", tick);
    return () => { clearInterval(t); document.removeEventListener("visibilitychange", tick); };
  }, [router, everyMs]);
  return <p className="muted small" role="status" aria-live="polite">{label}{at ? ` Last checked ${at}.` : ""}</p>;
}
