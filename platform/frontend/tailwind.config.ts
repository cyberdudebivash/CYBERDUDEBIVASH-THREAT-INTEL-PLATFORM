import type { Config } from "tailwindcss";
const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        apex: { primary: "#00d4ff", secondary: "#7c3aed", danger: "#ef4444" },
      },
    },
  },
  plugins: [],
};
export default config;
