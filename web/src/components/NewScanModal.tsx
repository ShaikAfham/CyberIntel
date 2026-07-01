"use client";
import { useState } from "react";
import { X, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { useRouter } from "next/navigation";

export function NewScanModal({ onClose }: { onClose: () => void }) {
  const router = useRouter();
  const [url, setUrl] = useState("https://");
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const scan = await api.createScan(url.trim(), token || undefined);
      onClose();
      router.push(`/scans/${scan.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Scan failed to start");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="glass w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold text-lg">New Security Scan</h2>
          <button onClick={onClose} className="text-white/40 hover:text-white">
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-xs text-white/50 mb-1 block">Target URL</label>
            <input
              type="url"
              value={url}
              onChange={e => setUrl(e.target.value)}
              required
              className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent"
              placeholder="https://example.com"
            />
          </div>

          <div>
            <button
              type="button"
              onClick={() => setShowToken(v => !v)}
              className="text-xs text-accent hover:underline"
            >
              {showToken ? "Hide" : "Add"} auth token (optional)
            </button>
            {showToken && (
              <input
                type="password"
                value={token}
                onChange={e => setToken(e.target.value)}
                className="mt-2 w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent"
                placeholder="Bearer token or API key — not stored"
                autoComplete="off"
              />
            )}
          </div>

          {error && <p className="text-critical text-xs">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-accent hover:bg-accent/80 disabled:opacity-50 text-white font-semibold py-2 rounded-lg flex items-center justify-center gap-2 transition-colors"
          >
            {loading && <Loader2 size={16} className="animate-spin" />}
            {loading ? "Starting…" : "Start Scan"}
          </button>
        </form>
      </div>
    </div>
  );
}
