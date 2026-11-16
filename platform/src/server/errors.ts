/** Error with an HTTP status and a stable machine code; message is safe to show to the caller. */
export class AppError extends Error {
  constructor(
    readonly status: 400 | 401 | 402 | 403 | 404 | 409 | 410 | 422 | 423 | 429 | 500 | 503,
    readonly code: string,
    message?: string,
    readonly extra?: Record<string, unknown>,
  ) {
    super(message ?? code);
    this.name = "AppError";
  }
}

export const notFound = () => new AppError(404, "not_found", "Not found");
export const forbidden = (reason = "forbidden") => new AppError(403, reason, "You do not have permission to do this");

export function isAppError(e: unknown): e is AppError {
  return e instanceof AppError;
}

/** Postgres unique violation (23505). Drizzle wraps driver errors, so the code may sit on `cause`. */
export function isUniqueViolation(e: unknown): boolean {
  for (let x = e as { code?: unknown; cause?: unknown } | undefined, i = 0; x && i < 4; x = x.cause as typeof x, i++) {
    if (x.code === "23505") return true;
  }
  return false;
}
