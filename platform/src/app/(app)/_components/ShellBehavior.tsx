"use client";
import { useEffect } from "react";
import { usePathname } from "next/navigation";

// The shell menus are native <details>, so they open and close without JS. This adds the expected extras:
// close on navigation, on a click outside and on Escape (returning focus to the menu button).
export function ShellBehavior() {
  const path = usePathname();

  useEffect(() => {
    document.querySelectorAll<HTMLDetailsElement>(".app details.menu[open]").forEach((d) => { d.open = false; });
  }, [path]);

  useEffect(() => {
    const onClick = (e: MouseEvent) => {
      document.querySelectorAll<HTMLDetailsElement>(".app details.menu[open]").forEach((d) => {
        if (!d.contains(e.target as Node)) d.open = false;
      });
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      const open = document.querySelector<HTMLDetailsElement>(".app details.menu[open]");
      if (!open) return;
      open.open = false;
      open.querySelector<HTMLElement>("summary")?.focus();
    };
    document.addEventListener("click", onClick);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("click", onClick); document.removeEventListener("keydown", onKey); };
  }, []);

  return null;
}
