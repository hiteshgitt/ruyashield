/** Joins class names, skipping falsy values, so callers can extend a component's classes. */
export function cn(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}
