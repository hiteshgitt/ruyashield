"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Icon, type IconName } from "./Icon";

export type NavGroup = { label: string; items: { href: string; label: string; icon: IconName }[] };

/** Grouped navigation; the current section is marked with aria-current. Used by the sidebar and the mobile menu. */
export function NavList({ groups }: { groups: NavGroup[] }) {
  const path = usePathname();
  const isActive = (href: string) => path === href || path.startsWith(`${href}/`);
  return (
    <>
      {groups.map((g) => (
        <div className="navgroup" key={g.label}>
          <p className="navgroup-label">{g.label}</p>
          <ul>
            {g.items.map((i) => (
              <li key={i.href}>
                <Link href={i.href} aria-current={isActive(i.href) ? "page" : undefined}>
                  <Icon name={i.icon} />{i.label}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </>
  );
}
