/** @type {import('tailwindcss').Config} */
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: token("bg"),
        surface: token("surface"),
        raised: token("raised"),
        line: token("line"),
        ink: token("ink"),
        muted: token("muted"),
        // Ops console: radar green is the brand and interactive colour, terminal amber the second accent.
        neon: token("neon"),
        amber: token("amber"),
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
        card: "0 1px 0 rgb(0 0 0 / 0.5)",
        lift: "0 24px 50px -24px rgb(0 0 0 / 0.9), 0 0 40px -16px rgb(43 255 136 / 0.25)",
        glow: "0 0 24px -6px rgb(43 255 136 / 0.6)",
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
