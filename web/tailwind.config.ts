import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        bg: "#0A0A0F",
        surface: "#1C1C1E",
        surface2: "#2C2C2E",
        border: "#3A3A3C",
        accent: "#0A84FF",
        critical: "#FF2D55",
        high: "#FF6B35",
        medium: "#FFB800",
        low: "#34C759",
        info: "#5AC8FA",
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
