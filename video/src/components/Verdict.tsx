// Verdict pill (DENY / ASK / ALLOW) stamped with a spring.
import { useCurrentFrame } from "remotion"
import { pop } from "../anim"
import { theme, type Verdict } from "../theme"

export const VerdictBadge: React.FC<{ verdict: Verdict; label: string; start: number; size?: number }> = ({ verdict, label, start, size = 26 }) => {
  const frame = useCurrentFrame()
  const p = pop(frame, start, 9)
  const color = theme[verdict]
  return (
    <div
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: size * 0.45,
        padding: `${size * 0.35}px ${size * 0.8}px`,
        borderRadius: 999,
        border: `2px solid ${color}`,
        background: `${color}22`,
        boxShadow: `0 0 ${40 * p}px ${color}66`,
        color,
        fontFamily: theme.sans,
        fontWeight: 800,
        fontSize: size,
        letterSpacing: "0.08em",
        opacity: Math.min(1, p * 1.5),
        transform: `scale(${1.6 - 0.6 * p}) rotate(${(1 - p) * -8}deg)`,
      }}
    >
      <div style={{ width: size * 0.42, height: size * 0.42, borderRadius: 99, background: color }} />
      {label}
    </div>
  )
}
