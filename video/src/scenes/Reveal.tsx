// 3. Logo: the shield draws itself, the name slides out of it, the tagline follows.
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion"
import { clamp, progress, rise, s } from "../anim"
import type { Copy } from "../content"
import { gradientText, theme } from "../theme"
import { Shield } from "../components/Shield"

export const Reveal: React.FC<{ copy: Copy }> = ({ copy }) => {
  const frame = useCurrentFrame()
  const name = progress(frame, 1.0, 0.8)
  const sweep = interpolate(frame, [s(1.6), s(2.6)], [-30, 130], clamp)
  return (
    <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", flexDirection: "column" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 46 * name }}>
        <Shield size={230} start={0.1} />
        <div style={{ overflow: "hidden", width: `${name * 1180}px`, whiteSpace: "nowrap", position: "relative" }}>
          <div style={{ fontFamily: theme.sans, fontWeight: 800, fontSize: 150, letterSpacing: "-0.045em", color: theme.text, transform: `translateX(${(1 - name) * -200}px)` }}>
            opencode<span style={gradientText}>-guard</span>
          </div>
          <div style={{ position: "absolute", inset: 0, background: `linear-gradient(100deg, transparent ${sweep - 12}%, rgba(255,255,255,0.35) ${sweep}%, transparent ${sweep + 12}%)`, mixBlendMode: "overlay" }} />
        </div>
      </div>
      <div style={{ marginTop: 40, fontFamily: theme.sans, fontSize: 46, fontWeight: 500, color: theme.muted, ...rise(frame, 1.7, 24) }}>{copy.revealTagline}</div>
    </AbsoluteFill>
  )
}
