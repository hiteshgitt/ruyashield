"use client";
import { useEffect, useRef, useState, type ReactNode } from "react";

/**
 * Wrapper that lets a wide table (or, with `as="pre"`, a long diff) scroll inside it instead of the page.
 * Content that scrolls must be reachable by keyboard (WCAG 2.1.1), so only a wrapper that actually overflows
 * becomes a focusable, labelled region; wide screens get no extra tab stops. The label is the nearest section
 * heading unless `label` is given.
 */
export function TableWrap({ as: Tag = "div", className, label, children }: { as?: "div" | "pre"; className?: string; label?: string; children: ReactNode }) {
  const ref = useRef<HTMLElement>(null);
  const [region, setRegion] = useState<string | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const sync = () => {
      const sideways = el.scrollWidth > el.clientWidth + 1, down = el.scrollHeight > el.clientHeight + 1;
      const head = label ?? headingBefore(el);
      setRegion(sideways || down ? `${head || "Table"} (${down ? "scrollable" : "scrolls sideways"})` : null);
    };
    sync();
    const ro = new ResizeObserver(sync);
    ro.observe(el);
    if (el.firstElementChild) ro.observe(el.firstElementChild);
    return () => ro.disconnect();
  }, [label]);

  return (
    <Tag ref={ref as never} className={["table-wrap", className].filter(Boolean).join(" ")}
      {...(region && { tabIndex: 0, role: "region", "aria-label": region })}>
      {children}
    </Tag>
  );
}

/** Text of the nearest heading above `el` in document order (walking back through siblings and ancestors). */
function headingBefore(el: Element): string | undefined {
  for (let node: Element | null = el; node && node.tagName !== "MAIN"; node = node.parentElement) {
    for (let sib = node.previousElementSibling; sib; sib = sib.previousElementSibling) {
      const h = sib.matches("h1, h2, h3") ? sib : sib.querySelector("h1, h2, h3");
      if (h?.textContent?.trim()) return h.textContent.trim();
    }
  }
  return document.querySelector("main h1")?.textContent?.trim();
}
