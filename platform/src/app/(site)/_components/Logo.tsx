import { cn } from "./cn";

/** RuyaShield mark: a shield whose inner aperture reads as an eye ("ruya", vision). */
export function Logo({ className }: { className?: string }) {
  return (
    <span className={cn("logo", className)}>
      <svg viewBox="0 0 32 32" aria-hidden="true" className="logo-mark">
        <defs>
          <linearGradient id="rs-g" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#c4b5fd" />
            <stop offset="1" stopColor="#7c3aed" />
          </linearGradient>
        </defs>
        <path d="M16 2.5 4.5 6.8v8.6c0 7 4.8 12.3 11.5 14.1 6.7-1.8 11.5-7.1 11.5-14.1V6.8L16 2.5Z" fill="none" stroke="url(#rs-g)" strokeWidth="2" strokeLinejoin="round" />
        <path d="M9 16.2c2-3.2 4.4-4.8 7-4.8s5 1.6 7 4.8c-2 3.2-4.4 4.8-7 4.8s-5-1.6-7-4.8Z" fill="none" stroke="url(#rs-g)" strokeWidth="1.8" strokeLinejoin="round" />
        <circle cx="16" cy="16.2" r="2.2" fill="#c4b5fd" />
      </svg>
      <span className="logo-word">RuyaShield</span>
    </span>
  );
}
