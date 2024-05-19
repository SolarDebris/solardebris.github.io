import type { Config } from "tailwindcss";
const config: Config = {
  content: [
      "./index.html", 
      "./app/*.{js,ts,jsx,tsx}",
      "./pages/**/*.{js,ts,jsx,tsx}",
      "./pages/*.{js,ts,jsx,tsx}",
      "./components/*.{js,ts,jsx,tsx}",
  ],
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
    fontFamily: {
        'sans': ["Space Grotesk", "JetBrainsMono Nerd Font", "sans-serif"],
        'serif': ["Space Grotesk", "JetBrainsMono Nerd Font", "sans-serif"],
        'mono': ["Space Grotesk", "JetBrainsMono Nerd Font", "sans-serif"],
        'grotesk': "Space Grotesk",
        'jetbrains': "JetBrainsMono Nerd Font"
    },
    extend: {},
  },
  plugins: [require("@tailwindcss/typography")],
};

export default config;

