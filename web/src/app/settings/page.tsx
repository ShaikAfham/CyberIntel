"use client";
import { useState } from "react";

export default function SettingsPage() {
  const [backendUrl, setBackendUrl] = useState(() =>
    (typeof window !== "undefined"
      ? localStorage.getItem("cyberintel_backend_url")
      : null) ?? "http://localhost:8000"
  );
  const [saved, setSaved] = useState(false);

  function save() {
    localStorage.setItem("cyberintel_backend_url", backendUrl);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <div className="p-6 space-y-6 max-w-xl">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-white/40 text-sm mt-0.5">Configure the CyberINTEL-AI dashboard</p>
      </div>

      <div className="glass p-5 space-y-4">
        <h2 className="font-semibold text-sm text-white/60">FastAPI Backend Connection</h2>
        <div>
          <label className="text-xs text-white/50 mb-1 block">Backend URL</label>
          <input
            type="url"
            value={backendUrl}
            onChange={e => setBackendUrl(e.target.value)}
            className="w-full bg-surface2 border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-accent"
          />
          <p className="text-xs text-white/30 mt-1">
            FastAPI backend address (default: <code>http://localhost:8000</code>). Changes take
            effect immediately — no rebuild needed.
          </p>
        </div>
        <button
          onClick={save}
          className="bg-accent hover:bg-accent/80 text-white px-4 py-2 rounded-lg text-sm font-medium"
        >
          {saved ? "✓ Saved" : "Save"}
        </button>
      </div>

      <div className="glass p-5 space-y-3">
        <h2 className="font-semibold text-sm text-white/60">About</h2>
        <div className="text-sm text-white/50 space-y-1">
          <p>CyberINTEL-AI Web Dashboard</p>
          <p>Version 1.0.0</p>
          <p>Stack: Next.js 14 + FastAPI + SQLAlchemy + TensorFlow.js</p>
        </div>
      </div>
    </div>
  );
}
