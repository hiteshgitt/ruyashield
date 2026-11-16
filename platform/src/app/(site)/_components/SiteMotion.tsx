"use client";

import { useEffect } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { SplitText } from "gsap/SplitText";
import { ScrambleTextPlugin } from "gsap/ScrambleTextPlugin";

gsap.registerPlugin(ScrollTrigger, SplitText, ScrambleTextPlugin);

/** Items revealed one after another when their list scrolls into view. */
const GROUPS = [
  ".guard-list > li", ".feature-list > *", ".facts > *", ".evidence > li", ".faq details", ".legend > *", ".flow-tabs > *",
];
/** Items with a section-specific choreography below. */
const SOLO = [
  ".problem-list > li", ".clients > *", ".roles > *", ".caps > li", ".plans > *", ".outcomes > *", ".handoff-steps > li",
  ".prio-table tbody tr", ".frame",
];
/** Things with their own animation, so the generic block reveal leaves them alone. */
const OWN = [...GROUPS, ...SOLO, "h2.display", ".claims", ".timeline", ".flow"].join(",");
/** Characters for the short "decode" effect on mono labels. */
const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/** Cards that get a pointer-following spotlight on hover. */
const SPOT = ".caps > li, .plan, .client, .handoff-steps > li, .outcomes > div, .claim";

/** Leaf blocks inside a [data-reveal] wrapper, skipping anything that animates on its own. */
function blocks(el: Element, out: Element[] = []) {
  for (const c of Array.from(el.children)) {
    if (c.matches(OWN)) continue;
    if (c.querySelector(OWN)) blocks(c, out);
    else out.push(c);
  }
  return out;
}

/**
 * All public-site motion. Nothing runs under prefers-reduced-motion: reduce, and nothing is hidden by the
 * server markup, so the page is complete without JavaScript. The only pre-hidden content is the hero, and only
 * while the html element carries `rs-motion` (set by the inline script in the layout); `rs-ready` lifts it, and
 * the script adds `rs-ready` itself after a few seconds in case this component never runs.
 */
export function SiteMotion() {
  useEffect(() => {
    const root = document.documentElement;
    const ready = () => root.classList.add("rs-ready");
    const rem = parseFloat(getComputedStyle(root).fontSize) || 16;
    const mm = gsap.matchMedia();

    mm.add("(prefers-reduced-motion: no-preference)", () => {
      const off: (() => void)[] = [];

      /* ---- hero intro ---- */
      const hero = document.querySelector<HTMLElement>(".hero");
      const title = hero?.querySelector<HTMLElement>(".hero-title");
      const consoleEl = hero?.querySelector<HTMLElement>(".console");
      if (hero && title && consoleEl) {
        const intro = gsap.timeline({ defaults: { ease: "power4.out", duration: 1 } });
        const titleSplit = SplitText.create(title, { type: "words", mask: "words" });
        intro
          .from(hero.querySelector(".eyebrow"), { autoAlpha: 0, x: -1.5 * rem, "--eb": 0, duration: .8 })
          .from(titleSplit.words, { yPercent: 110, duration: 1.1, stagger: .07 }, "<.1")
          .from(hero.querySelectorAll(".lead, .hero-cta"), { autoAlpha: 0, y: 1.5 * rem, stagger: .08 }, "<.35")
          .from(hero.querySelectorAll(".hero-facts li"), { autoAlpha: 0, x: -1 * rem, stagger: .08, duration: .7 }, "<.2")
          .from(consoleEl, { autoAlpha: 0, y: 4 * rem, rotationX: 14, rotationY: -10, scale: .94, transformPerspective: 1600, duration: 1.4 }, .25)
          .from(consoleEl.querySelectorAll(".console-asset, .console-cols h3"), { autoAlpha: 0, y: rem, stagger: .08, duration: .6 }, "<.45")
          .from(consoleEl.querySelectorAll(".checks li"), { autoAlpha: 0, x: -1.25 * rem, stagger: .09, duration: .6 }, "<.15")
          .from(consoleEl.querySelectorAll(".checks .pill"), { scale: .6, autoAlpha: 0, stagger: .09, duration: .5, ease: "back.out(2.4)" }, "<.2")
          .from(consoleEl.querySelector(".zealot-card"), { autoAlpha: 0, y: rem, duration: .6 }, "<");
        // Zealot's explanation "streams" in word by word, the way an assistant answer arrives.
        const zp = consoleEl.querySelector<HTMLElement>(".zealot-card p");
        const zSplit = zp ? SplitText.create(zp, { type: "words" }) : null;
        if (zSplit) intro.from(zSplit.words, { autoAlpha: .08, duration: .25, stagger: .035, ease: "none" }, "<.2");
        intro
          .from(consoleEl.querySelectorAll(".zealot-card .tags > *, .zealot-card footer"), { autoAlpha: 0, y: .5 * rem, stagger: .1, duration: .5 }, ">-.1")
          .from(consoleEl.querySelector(".console-foot"), { autoAlpha: 0, y: rem, duration: .6 }, "<");
        // "Awaiting re-test" pulses a few times, then stops (no endless loop).
        const wait = consoleEl.querySelector(".console-foot .pill");
        if (wait) intro.to(wait, { boxShadow: "0 0 0 .5rem rgba(245,177,76,0)", startAt: { boxShadow: "0 0 0 0 rgba(245,177,76,.45)" }, duration: 1.2, repeat: 3, ease: "power2.out" }, ">");
        ready();
        off.push(() => { titleSplit.revert(); zSplit?.revert(); });

        // As the hero scrolls away the console sinks back and the copy fades.
        gsap.to(consoleEl.parentElement, { yPercent: 8, scale: .95, rotationX: 8, transformPerspective: 1600, autoAlpha: .4, ease: "none",
          scrollTrigger: { trigger: hero, start: "top top", end: "bottom top", scrub: true } });
        gsap.to(hero.querySelector(".hero-copy"), { yPercent: -10, autoAlpha: .2, ease: "none",
          scrollTrigger: { trigger: hero, start: "top top", end: "bottom top", scrub: true } });
        gsap.to(hero, { "--hero-shift": "18%", ease: "none", scrollTrigger: { trigger: hero, start: "top top", end: "bottom top", scrub: true } });
      } else ready();

      /* ---- section headings: words rise out of a mask ---- */
      for (const h of gsap.utils.toArray<HTMLElement>(".site h2.display")) {
        SplitText.create(h, {
          type: "words", mask: "words", autoSplit: true,
          onSplit: (self) => gsap.from(self.words, { yPercent: 110, duration: 1, stagger: .05, ease: "power4.out",
            scrollTrigger: { trigger: h, start: "top 88%", once: true } }),
        });
      }

      /* ---- generic block reveal ---- */
      for (const wrap of gsap.utils.toArray<HTMLElement>("[data-reveal]")) {
        const items = blocks(wrap);
        if (items.length) gsap.from(items, { autoAlpha: 0, y: 2 * rem, duration: .9, stagger: .08, ease: "power3.out",
          scrollTrigger: { trigger: wrap, start: "top 85%", once: true } });
      }

      /* ---- staggered lists ---- */
      for (const sel of GROUPS) {
        const byParent = new Map<Element, Element[]>();
        for (const el of document.querySelectorAll(`.site ${sel}`)) {
          const p = el.parentElement!;
          byParent.set(p, [...(byParent.get(p) ?? []), el]);
        }
        for (const [parent, els] of byParent) {
          gsap.from(els, { autoAlpha: 0, y: 1.75 * rem, duration: .8, stagger: .07, ease: "power3.out",
            scrollTrigger: { trigger: parent, start: "top 88%", once: true } });
        }
      }

      /* ---- Zealot: claims arrive one by one, then the unsupported one is struck out ---- */
      const claims = document.querySelector(".claims");
      if (claims) {
        const dropped = claims.querySelector(".claim.dropped");
        const tl = gsap.timeline({ scrollTrigger: { trigger: claims, start: "top 80%", once: true } });
        tl.from(claims.querySelectorAll(".claim"), { autoAlpha: 0, x: 2 * rem, duration: .7, stagger: .18, ease: "power3.out" });
        if (dropped) {
          tl.from(dropped.querySelector("p"), { textDecorationColor: "rgba(248,113,113,0)", color: "#ecebf3", duration: .6 }, "+=.25")
            .from(dropped, { opacity: 1, borderColor: "rgba(248,113,113,.6)", duration: .6 }, "<")
            .from(dropped.querySelector(".pill"), { scale: .5, autoAlpha: 0, duration: .5, ease: "back.out(2.4)" }, "<");
        }
      }

      /* ---- FixProof timeline: the line draws with scroll and each step lights up as it is reached ---- */
      const timeline = document.querySelector<HTMLElement>(".timeline");
      if (timeline) {
        gsap.fromTo(timeline, { "--tl": 0 }, { "--tl": 1, ease: "none",
          scrollTrigger: { trigger: timeline, start: "top 80%", end: "bottom 55%", scrub: .6 } });
        for (const li of gsap.utils.toArray<HTMLElement>(".timeline > li")) {
          gsap.from(li, { autoAlpha: 0, y: 1.5 * rem, duration: .7, ease: "power3.out", scrollTrigger: { trigger: li, start: "top 85%", once: true } });
          ScrollTrigger.create({ trigger: li, start: "top 70%", onEnter: () => li.classList.add("is-lit"), onLeaveBack: () => li.classList.remove("is-lit") });
        }
      }

      /* ---- eyebrows: the rule draws in and the label decodes ---- */
      const texts = new Map<HTMLElement, string>();
      const decode = (el: HTMLElement, chars = GLYPHS, duration = .8) => {
        texts.set(el, el.textContent ?? "");
        return gsap.to(el, { scrambleText: { text: el.textContent ?? "", chars, revealDelay: .15, speed: .6 }, duration, ease: "none" });
      };
      off.push(() => texts.forEach((t, el) => { el.textContent = t; }));
      for (const eb of gsap.utils.toArray<HTMLElement>(".site section:not(.hero) .eyebrow")) {
        const tl = gsap.timeline({ scrollTrigger: { trigger: eb, start: "top 90%", once: true } });
        tl.fromTo(eb, { "--eb": 0 }, { "--eb": 1, duration: .7, ease: "power3.out" }).add(decode(eb), "<.1");
      }

      /* ---- product frames: unfold from a clipped card, then drift a little against the scroll on desktop ---- */
      for (const f of gsap.utils.toArray<HTMLElement>(".site figure.frame:not(.console)")) {
        const r = getComputedStyle(f).borderRadius || "1rem";
        gsap.fromTo(f, { clipPath: `inset(8% 6% 14% 6% round ${r})`, autoAlpha: 0, y: 3 * rem, rotationX: 8, transformPerspective: 1600, transformOrigin: "50% 0%" },
          { clipPath: `inset(0% 0% 0% 0% round ${r})`, autoAlpha: 1, y: 0, rotationX: 0, duration: 1.2, ease: "power4.out", clearProps: "clipPath",
            scrollTrigger: { trigger: f, start: "top 88%", once: true } });
      }

      /* ---- problem list: each item rises, then its rule sweeps across ---- */
      for (const li of gsap.utils.toArray<HTMLElement>(".problem-list > li")) {
        gsap.timeline({ scrollTrigger: { trigger: li, start: "top 88%", once: true } })
          .from(li, { autoAlpha: 0, y: 1.5 * rem, duration: .8, ease: "power3.out" })
          .fromTo(li, { "--ln": 0 }, { "--ln": 1, duration: 1, ease: "power2.inOut" }, "<.15")
          .from(li.querySelectorAll("h3, p"), { autoAlpha: 0, x: -1 * rem, stagger: .08, duration: .6, ease: "power3.out" }, "<.1");
      }

      /* ---- prioritization queue: rows slide in, then severity and status pop ---- */
      const prio = document.querySelector(".prio-table");
      if (prio) gsap.timeline({ scrollTrigger: { trigger: prio, start: "top 85%", once: true } })
        .from(prio.querySelectorAll("tbody tr"), { autoAlpha: 0, x: 2 * rem, stagger: .1, duration: .7, ease: "power3.out" }, .3)
        .from(prio.querySelectorAll(".pill"), { scale: .5, autoAlpha: 0, stagger: .05, duration: .45, ease: "back.out(2.4)" }, "-=.35");

      /* ---- agencies: client groups slide in, role chips pop in random order ---- */
      const clients = document.querySelector(".clients");
      if (clients) gsap.timeline({ scrollTrigger: { trigger: clients, start: "top 88%", once: true } })
        .from(clients.children, { autoAlpha: 0, x: 2.5 * rem, stagger: .12, duration: .8, ease: "power3.out" }, .3)
        .from(clients.querySelectorAll(".pill"), { scale: .5, autoAlpha: 0, stagger: .1, duration: .45, ease: "back.out(2.4)" }, "-=.4");
      const roles = document.querySelector(".roles");
      if (roles) gsap.from(roles.children, { scale: .6, autoAlpha: 0, duration: .5, ease: "back.out(2)", stagger: { each: .05, from: "random" },
        scrollTrigger: { trigger: roles, start: "top 92%", once: true } });

      /* ---- WebMonitor handoff: offer -> consent -> status, a highlight passing from step to step ---- */
      const steps = gsap.utils.toArray<HTMLElement>(".handoff-steps > li");
      if (steps.length) {
        const tl = gsap.timeline({ scrollTrigger: { trigger: steps[0].parentElement, start: "top 85%", once: true } });
        steps.forEach((li, i) => {
          const at = i * .45;
          tl.from(li, { autoAlpha: 0, y: 2 * rem, duration: .7, ease: "power3.out" }, at)
            .to(li, { borderColor: "rgba(167,139,250,.65)", boxShadow: "0 0 2rem -0.5rem rgba(139,92,246,.45)", duration: .35, yoyo: true, repeat: 1, ease: "power2.inOut" }, at + .35);
          const n = li.querySelector<HTMLElement>(".mono");
          if (n) tl.add(decode(n, "0123456789", .5), at + .1);
        });
      }

      /* ---- capabilities: grid-ordered stagger, keys decode ---- */
      const caps = document.querySelector(".caps");
      if (caps) {
        const tl = gsap.timeline({ scrollTrigger: { trigger: caps, start: "top 85%", once: true } });
        tl.from(caps.children, { autoAlpha: 0, y: 2 * rem, scale: .97, duration: .8, ease: "power3.out", stagger: { each: .07, grid: "auto", from: "start" } });
        caps.querySelectorAll<HTMLElement>(".mono").forEach((k, i) => tl.add(decode(k, GLYPHS.toLowerCase(), .6), .15 + i * .07));
      }

      /* ---- report: rows arrive in order, then the checksum decodes ---- */
      const report = document.querySelector(".report-doc");
      if (report) {
        const tl = gsap.timeline({ scrollTrigger: { trigger: report, start: "top 85%", once: true } });
        tl.from(report.querySelectorAll("h3, .rows li"), { autoAlpha: 0, y: rem, stagger: .12, duration: .6, ease: "power3.out" }, .4)
          .from(report.querySelectorAll(".rows .pill"), { scale: .5, autoAlpha: 0, stagger: .1, duration: .45, ease: "back.out(2.4)" }, "-=.3")
          .from(report.querySelector(".hash"), { autoAlpha: 0, duration: .4 }, "-=.1");
        const hv = report.querySelector<HTMLElement>(".hash-v");
        if (hv) tl.add(decode(hv, "0123456789abcdef", 1), "<");
      }

      /* ---- pricing: plans flip up in turn, the featured one settles last ---- */
      const plans = document.querySelector(".plans");
      if (plans) {
        const tl = gsap.timeline({ scrollTrigger: { trigger: plans, start: "top 85%", once: true } });
        tl.from(plans.children, { autoAlpha: 0, y: 3 * rem, rotationX: -18, transformPerspective: 1400, transformOrigin: "50% 0%", stagger: .14, duration: 1, ease: "power4.out" })
          .from(plans.querySelectorAll("li"), { autoAlpha: 0, x: -.75 * rem, stagger: .03, duration: .4, ease: "power2.out" }, "-=.6");
        const featured = plans.querySelector(".featured");
        if (featured) tl.from(featured, { boxShadow: "0 0 0 0 rgba(139,92,246,0)", duration: .8, ease: "power2.out" }, "-=.4");
      }

      /* ---- FixProof outcomes: cards rise, then each label pops ---- */
      const outcomes = document.querySelector(".outcomes");
      if (outcomes) gsap.timeline({ scrollTrigger: { trigger: outcomes, start: "top 88%", once: true } })
        .from(outcomes.children, { autoAlpha: 0, y: 1.75 * rem, stagger: .08, duration: .7, ease: "power3.out" })
        .from(outcomes.querySelectorAll(".pill"), { scale: .5, autoAlpha: 0, stagger: .08, duration: .45, ease: "back.out(2.4)" }, "-=.5");

      /* ---- FAQ: answers open and close smoothly (native <details> without JS) ---- */
      for (const d of gsap.utils.toArray<HTMLDetailsElement>(".faq details")) {
        const sum = d.querySelector("summary"), ans = d.querySelector<HTMLElement>("p");
        if (!sum || !ans) continue;
        const onClick = (e: Event) => {
          e.preventDefault();
          if (gsap.isTweening(ans)) return;
          if (!d.open) {
            d.open = true;
            gsap.from(ans, { height: 0, paddingBottom: 0, autoAlpha: 0, overflow: "hidden", duration: .45, ease: "power3.out", clearProps: "all" });
          } else {
            gsap.to(ans, { height: 0, paddingBottom: 0, autoAlpha: 0, overflow: "hidden", duration: .3, ease: "power2.in",
              onComplete: () => { d.open = false; gsap.set(ans, { clearProps: "all" }); } });
          }
        };
        sum.addEventListener("click", onClick);
        off.push(() => sum.removeEventListener("click", onClick));
      }

      /* ---- footer columns ---- */
      const foot = document.querySelector(".site-footer");
      if (foot) gsap.from(foot.querySelectorAll(".site-footer-top > *, .site-footer-bottom"), { autoAlpha: 0, y: 1.5 * rem, stagger: .08, duration: .8, ease: "power3.out",
        scrollTrigger: { trigger: foot, start: "top 92%", once: true } });

      /* ---- final CTA glow grows as it comes into view ---- */
      const final = document.querySelector<HTMLElement>(".final");
      if (final) gsap.fromTo(final, { "--glow": .6 }, { "--glow": 1.25, ease: "none", scrollTrigger: { trigger: final, start: "top bottom", end: "bottom bottom", scrub: true } });

      /* ---- reading progress in the header ---- */
      const bar = document.querySelector(".site-progress");
      if (bar) gsap.fromTo(bar, { scaleX: 0 }, { scaleX: 1, ease: "none", scrollTrigger: { start: 0, end: "max", scrub: .3 } });

      // Fonts change line breaks; recompute trigger positions once they've loaded.
      document.fonts?.ready.then(() => ScrollTrigger.refresh());
      return () => off.forEach((f) => f());
    });

    /* ---- desktop depth: frames drift slightly against the scroll ---- */
    mm.add("(prefers-reduced-motion: no-preference) and (min-width: 64rem)", () => {
      for (const f of gsap.utils.toArray<HTMLElement>(".site figure.frame:not(.console)")) {
        gsap.fromTo(f, { "--py": "1.5rem" }, { "--py": "-1.5rem", ease: "none", scrollTrigger: { trigger: f, start: "top bottom", end: "bottom top", scrub: true } });
      }
    });

    /* ---- pointer effects: desktop with a precise pointer only ---- */
    mm.add("(prefers-reduced-motion: no-preference) and (hover: hover) and (pointer: fine) and (min-width: 64rem)", () => {
      const off: (() => void)[] = [];
      const listen = (t: Element | Window, type: string, fn: (e: PointerEvent) => void) => {
        t.addEventListener(type, fn as EventListener);
        off.push(() => t.removeEventListener(type, fn as EventListener));
      };

      // Console tilts toward the pointer; a glow follows it.
      const stage = document.querySelector<HTMLElement>(".console-stage");
      const con = stage?.querySelector<HTMLElement>(".console");
      if (stage && con) {
        const rx = gsap.quickTo(con, "rotationX", { duration: .8, ease: "power3.out" });
        const ry = gsap.quickTo(con, "rotationY", { duration: .8, ease: "power3.out" });
        gsap.set(con, { transformPerspective: 1600 });
        listen(stage, "pointermove", (e) => {
          const r = stage.getBoundingClientRect();
          const px = (e.clientX - r.left) / r.width, py = (e.clientY - r.top) / r.height;
          rx((.5 - py) * 7); ry((px - .5) * 9);
          stage.style.setProperty("--mx", `${px * 100}%`);
          stage.style.setProperty("--my", `${py * 100}%`);
        });
        listen(stage, "pointerleave", () => { rx(0); ry(0); });
      }

      // Primary buttons lean toward the pointer.
      for (const btn of gsap.utils.toArray<HTMLElement>(".site .btn-primary")) {
        const x = gsap.quickTo(btn, "x", { duration: .5, ease: "power3.out" });
        const y = gsap.quickTo(btn, "y", { duration: .5, ease: "power3.out" });
        listen(btn, "pointermove", (e) => {
          const r = btn.getBoundingClientRect();
          x((e.clientX - r.left - r.width / 2) * .25); y((e.clientY - r.top - r.height / 2) * .35);
        });
        listen(btn, "pointerleave", () => { x(0); y(0); });
      }

      // Cards: a soft spotlight under the pointer.
      for (const card of gsap.utils.toArray<HTMLElement>(SPOT)) {
        listen(card, "pointermove", (e) => {
          const r = card.getBoundingClientRect();
          card.style.setProperty("--sx", `${e.clientX - r.left}px`);
          card.style.setProperty("--sy", `${e.clientY - r.top}px`);
        });
      }
      return () => off.forEach((f) => f());
    });

    return () => { mm.revert(); ready(); };
  }, []);

  return null;
}
