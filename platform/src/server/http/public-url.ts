// Behind Caddy/Cloudflare the app listens on 127.0.0.1:3200, so request.url / nextUrl carry the internal
// origin. Every URL the browser or the identity provider sees must use the public origin from APP_URL.
const origin = () => new URL(process.env.APP_URL ?? "http://localhost:3200").origin;

/** Absolute public URL for a path (or an already-absolute URL, which is returned unchanged). */
export const publicUrl = (pathOrUrl: string) => new URL(pathOrUrl, origin());

/** The current request's path and query on the public origin (for the OIDC redirect_uri match). */
export const publicRequestUrl = (u: URL) => new URL(u.pathname + u.search, origin());
