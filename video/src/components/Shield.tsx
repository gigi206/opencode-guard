// The logo: a shield whose outline is drawn, then filled, then a check mark appears.
import { useCurrentFrame } from "remotion"
import { pop, progress } from "../anim"
import { theme } from "../theme"

const SHIELD = "M100 12 L178 42 V102 C178 152 144 188 100 204 C56 188 22 152 22 102 V42 Z"
const CHECK = "M64 108 L90 134 L140 82"

export const Shield: React.FC<{ size?: number; start?: number; glow?: boolean }> = ({ size = 220, start = 0, glow = true }) => {
  const frame = useCurrentFrame()
  const draw = progress(frame, start, 0.9)
  const fill = progress(frame, start + 0.6, 0.5)
  const check = progress(frame, start + 0.9, 0.45)
  const scale = 0.85 + 0.15 * pop(frame, start)
  return (
    <svg width={size} height={size * 1.08} viewBox="0 0 200 216" style={{ transform: `scale(${scale})`, overflow: "visible" }}>
      <defs>
        <linearGradient id="shield-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor={theme.accent} />
          <stop offset="100%" stopColor={theme.accent2} />
        </linearGradient>
        <filter id="shield-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="14" />
        </filter>
      </defs>
      {glow && <path d={SHIELD} fill="url(#shield-grad)" opacity={fill * 0.35} filter="url(#shield-glow)" />}
      <path d={SHIELD} fill="url(#shield-grad)" fillOpacity={fill} stroke="url(#shield-grad)" strokeWidth={7} strokeLinejoin="round" pathLength={1} strokeDasharray={1} strokeDashoffset={1 - draw} />
      <path d={CHECK} fill="none" stroke="#FFFFFF" strokeWidth={13} strokeLinecap="round" strokeLinejoin="round" pathLength={1} strokeDasharray={1} strokeDashoffset={1 - check} />
    </svg>
  )
}
