import { cn } from "./cn";

/** RuyaShield logo: the shield-and-R mark (public/brand) with the name as live text, "Shield" in the brand orange. */
export function Logo({ className }: { className?: string }) {
  return (
    <span className={cn("logo", className)}>
      {/* eslint-disable-next-line @next/next/no-img-element -- a 128 px static mark; no resizing needed */}
      <img src="/brand/ruyashield-mark-128.png" alt="" width={30} height={30} className="logo-mark" />
      <span className="logo-word">Ruya<span className="logo-accent">Shield</span></span>
    </span>
  );
}
