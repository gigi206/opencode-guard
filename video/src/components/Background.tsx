// Animated backdrop of every scene: LINAGORA's light grey with drifting diagonal stripes (as on linagora.com), a
// faint grid and two soft red glows.
import { AbsoluteFill, useCurrentFrame } from "remotion"
import { theme } from "../theme"

export const Background: React.FC = () => {
  const frame = useCurrentFrame()
  const drift = (frame * 0.35) % 80
  const stripes = (frame * 0.6) % 120
  const glowX = 50 + Math.sin(frame / 90) * 18
  const glowY = 40 + Math.cos(frame / 110) * 12
  return (
    <AbsoluteFill style={{ backgroundColor: theme.bg, overflow: "hidden" }}>
      <AbsoluteFill
        style={{
          backgroundImage: "repeating-linear-gradient(120deg, rgba(255,255,255,0.9) 0 18px, transparent 18px 120px)",
          backgroundPosition: `${stripes}px 0`,
          opacity: 0.8,
        }}
      />
      <AbsoluteFill
        style={{
          background: `radial-gradient(ellipse 50% 42% at ${glowX}% ${glowY}%, ${theme.accent}14 0%, transparent 70%),
            radial-gradient(ellipse 40% 40% at ${100 - glowX}% ${100 - glowY / 2}%, ${theme.accent2}10 0%, transparent 70%)`,
        }}
      />
      <AbsoluteFill
        style={{
          backgroundImage: `linear-gradient(rgba(74,78,82,0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(74,78,82,0.05) 1px, transparent 1px)`,
          backgroundSize: "80px 80px",
          backgroundPosition: `${drift}px ${drift}px`,
          maskImage: "radial-gradient(ellipse 70% 70% at 50% 50%, black 30%, transparent 100%)",
        }}
      />
    </AbsoluteFill>
  )
}
