// Colors, fonts and sizes of the whole video, in LINAGORA's colors (linagora.com). Change a value here and every
// scene follows.
import "@fontsource/inter/400.css"
import "@fontsource/inter/500.css"
import "@fontsource/inter/600.css"
import "@fontsource/inter/700.css"
import "@fontsource/inter/800.css"
import "@fontsource/jetbrains-mono/400.css"
import "@fontsource/jetbrains-mono/700.css"

export const theme = {
  // Page: light, like linagora.com.
  bg: "#F7F8F9",
  card: "#FFFFFF",
  cardBorder: "rgba(74,78,82,0.14)",
  text: "#1E2125",
  muted: "#4A4E52",
  faint: "#9AA0A6",

  // Brand: the red of the LINAGORA logo and the deeper red of the site.
  accent: "#E20111",
  accent2: "#C42D43",
  link: "#0779BF",

  // One color per verdict, readable on the light page.
  deny: "#E20111",
  ask: "#D97706",
  allow: "#12A150",
  model: "#6D4AFF",
  redacted: "#0779BF",

  sans: "Inter, sans-serif",
  mono: "'JetBrains Mono', monospace",
} as const

/** Dark windows (terminal, OpenCode): brighter verdict colors, as in a real terminal. */
export const term = {
  bg: "#16181D",
  bar: "#1E2127",
  border: "rgba(255,255,255,0.08)",
  text: "#F1F3F5",
  muted: "#8A90A2",
  deny: "#FF4D5E",
  ask: "#FFB547",
  allow: "#3BE39A",
  model: "#B58CFF",
  accent: "#FF5A66",
  link: "#4FB3F6",
} as const

export const gradient = `linear-gradient(100deg, ${theme.accent} 0%, ${theme.accent2} 100%)`

/** Text filled with the brand gradient. */
export const gradientText = {
  backgroundImage: gradient,
  WebkitBackgroundClip: "text",
  backgroundClip: "text",
  color: "transparent",
} as const

/** Soft shadow of white cards on the page. */
export const cardShadow = "0 24px 60px rgba(30,33,37,0.10), 0 2px 6px rgba(30,33,37,0.06)"

export type Verdict = "deny" | "ask" | "allow" | "model"
