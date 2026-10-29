// 2. `rm -rf ~` is typed, the screen glitches red: "One bad command is enough."
import { AbsoluteFill, interpolate, random, useCurrentFrame } from "remotion"
import { clamp, rise, s, typed } from "../anim"
import type { Copy } from "../content"
import { term, theme } from "../theme"
import { Window } from "../components/Terminal"
import { Words } from "../components/Title"

const COMMAND = "rm -rf ~"
const HIT = 0.85

export const Danger: React.FC<{ copy: Copy }> = ({ copy }) => {
  const frame = useCurrentFrame()
  const hit = frame - s(HIT)
  const flash = interpolate(hit, [0, 2, 14], [0, 0.55, 0], clamp)
  const shake = hit >= 0 && hit < 12 ? (random(`shake${frame}`) - 0.5) * 30 * (1 - hit / 12) : 0
  const glitch = hit >= 0 && hit < 10
  return (
    <AbsoluteFill style={{ transform: `translate(${shake}px, ${shake * 0.4}px)` }}>
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", flexDirection: "column", gap: 70 }}>
        <div style={{ position: "relative" }}>
          <Window title="zsh" width={760}>
            <div style={{ padding: "30px 34px", fontFamily: theme.mono, fontSize: 44, color: term.text, whiteSpace: "pre" }}>
              <span style={{ color: term.allow, fontWeight: 700 }}>❯ </span>
              {typed(frame, COMMAND, 0.05, 14)}
              <span style={{ opacity: Math.floor(frame / 8) % 2 ? 1 : 0, background: term.text }}>&nbsp;</span>
            </div>
          </Window>
          {glitch && (
            <>
              <div style={{ position: "absolute", inset: 0, transform: `translateX(${random(`g${frame}`) * 24 - 12}px)`, border: `3px solid ${theme.deny}`, borderRadius: 18 }} />
              <div style={{ position: "absolute", left: -40, right: -40, top: `${random(`y${frame}`) * 80}%`, height: 14, background: theme.deny, opacity: 0.6 }} />
            </>
          )}
        </div>
        <div style={{ textAlign: "center" }}>
          <Words text={copy.dangerTitle} start={HIT + 0.1} size={92} />
          <div style={{ display: "flex", gap: 40, justifyContent: "center", marginTop: 34 }}>
            {copy.dangerItems.map((item, i) => (
              <div key={item} style={{ fontFamily: theme.mono, fontSize: 28, color: theme.deny, ...rise(frame, HIT + 0.8 + i * 0.18, 20) }}>
                ✕ {item}
              </div>
            ))}
          </div>
        </div>
      </AbsoluteFill>
      <AbsoluteFill style={{ background: theme.deny, opacity: flash * 0.6 }} />
    </AbsoluteFill>
  )
}
