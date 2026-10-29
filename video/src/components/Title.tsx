// Kinetic typography: words rise in one after another.
import { useCurrentFrame } from "remotion"
import { rise } from "../anim"
import { theme } from "../theme"

export const Words: React.FC<{
  text: string
  start: number
  stagger?: number
  size?: number
  weight?: number
  color?: string
  style?: React.CSSProperties
  wordStyle?: (word: string, index: number) => React.CSSProperties | undefined
}> = ({ text, start, stagger = 0.07, size = 96, weight = 800, color = theme.text, style, wordStyle }) => {
  const frame = useCurrentFrame()
  return (
    <div style={{ fontFamily: theme.sans, fontSize: size, fontWeight: weight, color, letterSpacing: "-0.035em", lineHeight: 1.08, ...style }}>
      {text.split(" ").map((word, i) => (
        <span key={i} style={{ display: "inline-block", marginRight: "0.25em", ...rise(frame, start + i * stagger, size * 0.5), ...wordStyle?.(word, i) }}>
          {word}
        </span>
      ))}
    </div>
  )
}

/** Small uppercase label above a title. */
export const Eyebrow: React.FC<{ text: string; start: number; color?: string }> = ({ text, start, color = theme.accent2 }) => {
  const frame = useCurrentFrame()
  return (
    <div style={{ fontFamily: theme.mono, fontSize: 22, letterSpacing: "0.2em", textTransform: "uppercase", color, ...rise(frame, start, 20) }}>
      {text}
    </div>
  )
}
