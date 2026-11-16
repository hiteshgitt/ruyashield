import type { ReactNode } from "react";
import { cn } from "./cn";

/**
 * Marks a block for the scroll reveal in <SiteMotion>. The markup itself is static, so the content is visible
 * without JavaScript and with reduced motion; GSAP only hides and reveals it when motion is allowed.
 */
export function Reveal({ children, className, as: Tag = "div" }: { children: ReactNode; className?: string; as?: "div" | "section" }) {
  return <Tag data-reveal="" className={cn(className)}>{children}</Tag>;
}
