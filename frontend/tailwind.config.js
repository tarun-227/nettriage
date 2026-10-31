/** @type {import('tailwindcss').Config} */
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["selector", '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: token("bg"),
        surface: token("surface"),
        raised: token("raised"),
        line: token("line"),
        ink: token("ink"),
        muted: token("muted"),
        // Brand: navy and muted gold. "primary" is the text-safe interactive colour for the theme.
        navy: token("navy"),
        gold: token("gold"),
        primary: token("primary"),
        "on-primary": token("on-primary"),
        accent: token("primary"),
        attack: token("attack"),
        fault: token("fault"),
        review: token("review"),
        benign: token("benign"),
      },
      fontFamily: {
        sans: ["ui-sans-serif", "system-ui", "-apple-system", "Segoe UI", "Roboto", "Helvetica Neue", "Arial",
          "sans-serif"],
        serif: ["Iowan Old Style", "Palatino Linotype", "Palatino", "Book Antiqua", "Georgia", "ui-serif", "serif"],
        mono: ["ui-monospace", "Cascadia Code", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
      boxShadow: {
        card: "0 1px 2px rgb(27 42 74 / 0.06), 0 2px 8px rgb(27 42 74 / 0.05)",
        lift: "0 10px 30px -10px rgb(27 42 74 / 0.35), 0 4px 10px -4px rgb(27 42 74 / 0.2)",
        gold: "0 8px 24px -8px rgb(201 162 39 / 0.55)",
      },
      keyframes: {
        sway: { "0%": { transform: "rotateX(58deg) rotateZ(-34deg)" }, "100%": { transform: "rotateX(56deg) rotateZ(-44deg)" } },
        hop: {
          "0%": { transform: "translate3d(var(--x1), var(--y1), 10px)", opacity: "0" },
          "10%": { opacity: "1" },
          "90%": { opacity: "1" },
          "100%": { transform: "translate3d(var(--x2), var(--y2), 10px)", opacity: "0" },
        },
        pulse3d: { "0%,100%": { opacity: "0.35", transform: "translateZ(2px) scale(1)" },
          "50%": { opacity: "0.9", transform: "translateZ(2px) scale(1.6)" } },
        spinY: { "0%": { transform: "rotateX(62deg) rotateZ(0deg)" }, "100%": { transform: "rotateX(62deg) rotateZ(360deg)" } },
        float: { "0%,100%": { transform: "translateY(0)" }, "50%": { transform: "translateY(-6px)" } },
      },
      animation: {
        sway: "sway 9s ease-in-out infinite alternate",
        hop: "hop var(--dur, 2.4s) linear infinite",
        pulse3d: "pulse3d 2.2s ease-in-out infinite",
        spinY: "spinY 26s linear infinite",
        float: "float 5s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};
