// 1. "Your AI agent has a shell." with dangerous commands drifting behind.
import { AbsoluteFill, useCurrentFrame } from "remotion"
import { progress, rise } from "../anim"
import { HOOK_COMMANDS, type Copy } from "../content"
import { gradientText, term, theme } from "../theme"
import { Words } from "../components/Title"

// Deterministic placement of the drifting chips: [x %, y %, depth 0..1].
const PLACES: [number, number, number][] = [
  [6, 14, 0.9], [62, 9, 0.5], [30, 80, 0.7], [72, 84, 1], [2, 52, 0.4], [80, 46, 0.6], [44, 4, 0.3], [4, 76, 0.35],
]

export const Hook: React.FC<{ copy: Copy }> = ({ copy }) => {
  const frame = useCurrentFrame()
  return (
    <AbsoluteFill>
      {HOOK_COMMANDS.map((command, i) => {
        const [x, y, depth] = PLACES[i % PLACES.length]!
        const appear = progress(frame, 0.1 + i * 0.12, 0.8)
        return (
          <div
            key={command}
            style={{
              position: "absolute",
              left: `${x}%`,
              top: `${y}%`,
              transform: `translateX(${frame * (0.4 + depth * 1.1)}px) rotate(${(i % 2 ? 1 : -1) * 3}deg) scale(${0.7 + depth * 0.5})`,
              opacity: appear * (0.12 + depth * 0.33),
              filter: `blur(${(1 - depth) * 3}px)`,
              fontFamily: theme.mono,
              fontSize: 30,
              color: i % 3 === 0 ? term.deny : term.text,
              padding: "12px 22px",
              borderRadius: 12,
              border: `1px solid ${i % 3 === 0 ? `${term.deny}66` : term.border}`,
              background: term.bg,
              whiteSpace: "pre",
            }}
          >
            <span style={{ color: term.allow }}>$ </span>
            {command}
          </div>
        )
      })}
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", textAlign: "center" }}>
        <Words text={copy.hookTitle[0]!} start={0.3} size={130} />
        <Words text={copy.hookTitle[1]!} start={0.55} size={130} wordStyle={(_, i) => (i === copy.hookTitle[1]!.split(" ").length - 1 ? gradientText : undefined)} />
        <div style={{ marginTop: 36, fontFamily: theme.sans, fontSize: 38, color: theme.muted, ...rise(frame, 1.5, 20) }}>{copy.hookSub}</div>
      </AbsoluteFill>
    </AbsoluteFill>
  )
}
