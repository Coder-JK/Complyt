"use client";

import { usePathname } from "next/navigation";
import { MobileSidebar } from "./sidebar";

const PAGE_TITLES: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/controls": "Controls",
  "/evidence": "Evidence Runs",
  "/exports": "Exports",
  "/settings": "Settings",
};

export function Header() {
  const pathname = usePathname();
  const title =
    Object.entries(PAGE_TITLES).find(([path]) =>
      pathname.startsWith(path)
    )?.[1] ?? "Complyt";

  return (
    <header className="flex h-14 items-center gap-4 border-b bg-background px-4 lg:px-6">
      <MobileSidebar />
      <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
    </header>
  );
}
