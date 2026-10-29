// 9. Key numbers, counted up.
import { AbsoluteFill, useCurrentFrame } from "remotion"
import { progress, rise } from "../anim"
import type { Copy } from "../content"
import { cardShadow, gradientText, theme } from "../theme"

export const Stats: React.FC<{ copy: Copy }> = ({ copy }) => {
  const frame = useCurrentFrame()
  return (
    <AbsoluteFill style={{ flexDirection: "row", justifyContent: "center", alignItems: "center", gap: 40 }}>
      {copy.stats.map((stat, i) => {
        const start = 0.2 + i * 0.18
        const number = Number(stat.value)
        const value = Number.isFinite(number) && number > 0 ? Math.round(number * progress(frame, start, 1.2)) : stat.value
        return (
          <div key={stat.label} style={{ width: 380, textAlign: "center", padding: "50px 0", borderRadius: 28, background: theme.card, boxShadow: cardShadow, border: `1px solid ${theme.cardBorder}`, ...rise(frame, start, 50) }}>
            <div style={{ fontFamily: theme.sans, fontWeight: 800, fontSize: 150, letterSpacing: "-0.05em", lineHeight: 1, ...gradientText }}>{value}</div>
            <div style={{ marginTop: 18, fontFamily: theme.sans, fontSize: 30, color: theme.muted }}>{stat.label}</div>
          </div>
        )
      })}
    </AbsoluteFill>
  )
}
