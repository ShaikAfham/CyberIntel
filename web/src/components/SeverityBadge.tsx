import { cn, SEV_BG } from "@/lib/utils";
import type { Severity } from "@/types/api";

export function SeverityBadge({ sev }: { sev: Severity }) {
  return (
    <span className={cn("text-xs font-semibold px-2 py-0.5 rounded border", SEV_BG[sev])}>
      {sev}
    </span>
  );
}
