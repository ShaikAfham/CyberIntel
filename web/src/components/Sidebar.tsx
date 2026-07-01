"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Shield, Search, FileText, Settings, ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/scans", label: "Scans", icon: Search },
  { href: "/findings", label: "Findings", icon: Shield },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings },
];

export function Sidebar() {
  const path = usePathname();
  return (
    <aside className="w-56 flex-none flex flex-col border-r border-border bg-surface">
      <div className="px-5 py-4 border-b border-border">
        <span className="text-accent font-bold text-lg tracking-tight">
          CyberINTEL<span className="text-white/50">-AI</span>
        </span>
        <p className="text-xs text-white/30 mt-0.5">Threat Intelligence</p>
      </div>
      <nav className="flex-1 p-3 space-y-1">
        {NAV.map(({ href, label, icon: Icon }) => {
          const active = href === "/" ? path === "/" : path.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors",
                active
                  ? "bg-accent/10 text-accent font-medium"
                  : "text-white/50 hover:text-white hover:bg-surface2",
              )}
            >
              <Icon size={16} />
              {label}
              {active && <ChevronRight size={12} className="ml-auto" />}
            </Link>
          );
        })}
      </nav>
      <div className="px-4 py-3 border-t border-border">
        <p className="text-xs text-white/20">v1.0.0  ·  FastAPI + Next.js</p>
      </div>
    </aside>
  );
}
