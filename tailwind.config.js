/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    colors: {
      "dr-background": "#282a36",
      "dr-current_line": "#44475a",
      "dr-foreground": "#f8f8f2",
      "dr-comment": "#6272a4",
      "dr-cyan": "#8be9fd",
      "dr-orange": "#ffb86c",
      "dr-pink": "#ff79c6",
      "dr-purple": "#bd93f9",
      "dr-red": "#ff5555",
      "dr-yellow": "#f1fa8c",
    },
    extend: {},
  },
  plugins: [require("@tailwindcss/typography")],
};
