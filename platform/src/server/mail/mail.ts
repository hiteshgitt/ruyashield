import nodemailer, { type Transporter } from "nodemailer";

// One SMTP transport for every email RuyaShield sends (invites, notifications, sign-in emails). In production
// SMTP_* point at Resend's SMTP relay; locally they point at Mailpit.

let transport: Transporter | undefined;
export function mailTransport(): Transporter {
  transport ??= nodemailer.createTransport({
    host: process.env.SMTP_HOST || "127.0.0.1", port: Number(process.env.SMTP_PORT || 1025),
    secure: process.env.SMTP_SECURE === "true",
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS ?? "" } : undefined,
  });
  return transport;
}

export const mailFrom = () => process.env.MAIL_FROM || "RuyaShield <no-reply@ruyashield.local>";
export const appLink = (path: string) => new URL(path, process.env.APP_URL ?? "http://localhost:3200").toString();

export interface Mail { to: string; subject: string; text: string; html?: string }

export async function sendMail(m: Mail, transporter: Pick<Transporter, "sendMail"> = mailTransport()) {
  await transporter.sendMail({ from: mailFrom(), ...m });
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
const FONT = "font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif";

/** A branded, table-based email: dark header with the shield, one message, one button. */
export function brandedEmail(o: { preheader: string; title: string; paragraphs: string[]; button?: { label: string; href: string }; footnote?: string }): string {
  const logo = appLink("/brand/ruyashield-mark-128.png");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light"><title>${esc(o.title)}</title></head>
<body style="margin:0;padding:0;background:#07060c">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">${esc(o.preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#07060c;background-image:radial-gradient(600px 300px at 80% 0%,rgba(255,90,31,.18),transparent 70%),radial-gradient(700px 360px at 0% 30%,rgba(139,92,246,.22),transparent 70%)"><tr><td align="center" style="padding:36px 14px">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px">
  <tr><td style="padding:0 4px 18px"><table role="presentation" cellpadding="0" cellspacing="0"><tr>
    <td><img src="${logo}" width="34" height="34" alt="" style="display:block;border:0"></td>
    <td style="padding-left:10px;${FONT};font-size:18px;font-weight:700;color:#ecebf3">Ruya<span style="color:#ff5a1f">Shield</span></td>
  </tr></table></td></tr>
  <tr><td style="border-radius:20px;background:#171424;border:1px solid #2a2440;padding:34px 32px;${FONT}">
    <div style="height:3px;border-radius:3px;background:#ff5a1f;background-image:linear-gradient(90deg,#ff8a1f,#ff4d12,#8b5cf6);margin-bottom:24px"></div>
    <div style="font-size:24px;line-height:1.25;font-weight:700;color:#ffffff">${esc(o.title)}</div>
    ${o.paragraphs.map((p) => `<p style="font-size:15px;line-height:1.6;color:#b0adc2;margin:14px 0 0">${esc(p)}</p>`).join("")}
    ${o.button ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin-top:26px"><tr><td style="border-radius:12px;background:#8b5cf6;background-image:linear-gradient(135deg,#ff6a1f,#8b5cf6)">
      <a href="${esc(o.button.href)}" style="display:inline-block;padding:14px 28px;${FONT};font-size:15px;font-weight:700;color:#ffffff;text-decoration:none">${esc(o.button.label)}</a></td></tr></table>
      <p style="font-size:12px;line-height:1.5;color:#8f8ba5;margin:18px 0 0;word-break:break-all">Or paste this link into your browser:<br><span style="color:#c4b5fd">${esc(o.button.href)}</span></p>` : ""}
    ${o.footnote ? `<p style="font-size:12px;line-height:1.5;color:#8f8ba5;margin:22px 0 0;padding-top:16px;border-top:1px solid #2a2440">${esc(o.footnote)}</p>` : ""}
  </td></tr>
  <tr><td align="center" style="padding:20px 8px 0;${FONT};font-size:11px;line-height:1.6;color:#6f6a86">RuyaShield by Ruyalab · authorized-scope website security</td></tr>
</table></td></tr></table></body></html>`;
}
