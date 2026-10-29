// 4. How a tool call is decided: local rules first, then the decision model. Glowing packets travel the paths.
import { AbsoluteFill, useCurrentFrame } from "remotion"
import { pop, progress, rise, s } from "../anim"
import { AI_GATEWAY, DECISION_MODEL, type Copy } from "../content"
import { cardShadow, theme, type Verdict } from "../theme"
import { Eyebrow, Words } from "../components/Title"

type P = [number, number]

// Layout (px, 1920×1080).
const CALL: P = [240, 560]
const LOCAL: P = [740, 560]
const MODEL: P = [1290, 560]
const NODE_W = 480
const LOCAL_OUT: Record<"deny" | "ask", P> = { deny: [600, 830], ask: [900, 830] }
const OUT: Record<"allow" | "ask" | "deny", P> = { allow: [1720, 410], ask: [1720, 560], deny: [1720, 710] }

/** Packets: path, departure (s), travel time (s), and the verdict they end on. */
const PACKETS: { path: P[]; start: number; duration: number; verdict: Verdict; local?: boolean }[] = [
  { path: [CALL, LOCAL, LOCAL_OUT.deny], start: 1.9, duration: 1.0, verdict: "deny", local: true },
  { path: [CALL, LOCAL, MODEL, OUT.allow], start: 3.3, duration: 1.5, verdict: "allow" },
  { path: [CALL, LOCAL, MODEL, OUT.ask], start: 5.2, duration: 1.5, verdict: "ask" },
]

function along(path: P[], t: number): P {
  const lengths = path.slice(1).map((p, i) => Math.hypot(p[0] - path[i]![0], p[1] - path[i]![1]))
  let d = t * lengths.reduce((a, b) => a + b, 0)
  for (let i = 0; i < lengths.length; i++) {
    if (d <= lengths[i]! || i === lengths.length - 1) {
      const k = Math.min(1, d / lengths[i]!)
      const [a, b] = [path[i]!, path[i + 1]!]
      return [a[0] + (b[0] - a[0]) * k, a[1] + (b[1] - a[1]) * k]
    }
    d -= lengths[i]!
  }
  return path.at(-1)!
}

const Node: React.FC<{ at: P; w: number; h: number; title: string; sub: string; start: number; color: string; extra?: React.ReactNode }> = ({ at, w, h, title, sub, start, color, extra }) => {
  const frame = useCurrentFrame()
  const p = pop(frame, start, 13)
  return (
    <div style={{ position: "absolute", left: at[0] - w / 2, top: at[1] - h / 2, width: w, height: h, borderRadius: 22, border: `2px solid ${color}`, background: theme.card, boxShadow: `${cardShadow}, 0 0 50px ${color}22`, display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", gap: 10, padding: "0 20px", textAlign: "center", whiteSpace: "nowrap", transform: `scale(${p})`, opacity: Math.min(1, p) }}>
      <div style={{ fontFamily: theme.sans, fontWeight: 700, fontSize: 38, color: theme.text }}>{title}</div>
      <div style={{ fontFamily: theme.mono, fontSize: 19, color: theme.muted }}>{sub}</div>
      {extra}
    </div>
  )
}

export const Flow: React.FC<{ copy: Copy }> = ({ copy }) => {
  const frame = useCurrentFrame()
  const lines = progress(frame, 0.9, 0.8)
  const hits = PACKETS.map((packet) => frame >= s(packet.start + packet.duration))
  const lit = (verdict: Verdict, local = false) => PACKETS.some((packet, i) => hits[i] && packet.verdict === verdict && Boolean(packet.local) === local)
  const edges: P[][] = [[CALL, LOCAL], [LOCAL, MODEL], [LOCAL, LOCAL_OUT.deny], [LOCAL, LOCAL_OUT.ask], [MODEL, OUT.allow], [MODEL, OUT.ask], [MODEL, OUT.deny]]
  return (
    <AbsoluteFill>
      <div style={{ position: "absolute", top: 110, width: "100%", textAlign: "center" }}>
        <Eyebrow text="tool.execute.before" start={0} />
        <Words text={copy.flowTitle} start={0.1} size={56} weight={700} style={{ marginTop: 16, padding: "0 120px" }} stagger={0.04} />
      </div>
      <svg width={1920} height={1080} style={{ position: "absolute" }}>
        {edges.map((edge, i) => (
          <polyline key={i} points={edge.map((p) => p.join(",")).join(" ")} fill="none" stroke="rgba(74,78,82,0.35)" strokeWidth={3} strokeDasharray="10 10" pathLength={1} strokeDashoffset={0} opacity={lines} />
        ))}
        {PACKETS.map((packet, i) => {
          const t = progress(frame, packet.start, packet.duration)
          if (t <= 0 || t >= 1) return null
          const [x, y] = along(packet.path, t)
          const color = theme[packet.verdict]
          return (
            <g key={i}>
              <circle cx={x} cy={y} r={34} fill={color} opacity={0.25} />
              <circle cx={x} cy={y} r={13} fill={color} />
            </g>
          )
        })}
      </svg>
      {/* Tool call pill */}
      <div style={{ position: "absolute", left: CALL[0] - 150, top: CALL[1] - 45, width: 300, height: 90, borderRadius: 45, background: theme.card, boxShadow: cardShadow, border: `2px solid ${theme.cardBorder}`, display: "flex", alignItems: "center", justifyContent: "center", fontFamily: theme.mono, fontSize: 28, color: theme.text, ...rise(frame, 0.5, 20) }}>
        {copy.flowToolCall}
      </div>
      <Node at={LOCAL} w={NODE_W} h={180} title={copy.flowLocal} sub={copy.flowLocalSub} start={0.7} color={theme.accent} />
      <Node
        at={MODEL}
        w={NODE_W}
        h={200}
        title={copy.flowModel}
        sub={copy.flowModelSub}
        start={0.95}
        color={theme.model}
        extra={<div style={{ fontFamily: theme.mono, fontSize: 18, color: theme.model }}>{DECISION_MODEL} · {AI_GATEWAY}</div>}
      />
      {/* Local outcomes */}
      {(["deny", "ask"] as const).map((v, i) => (
        <Outcome key={v} at={LOCAL_OUT[v]} label={copy.verdicts[v]} verdict={v} on={lit(v, true)} start={0.9 + i * 0.1} />
      ))}
      {/* Model outcomes */}
      {(["allow", "ask", "deny"] as const).map((v, i) => (
        <Outcome key={v} at={OUT[v]} label={copy.verdicts[v]} verdict={v} on={lit(v)} start={1.1 + i * 0.1} />
      ))}
      <div style={{ position: "absolute", left: MODEL[0] - NODE_W / 2, width: NODE_W, top: MODEL[1] + 130, textAlign: "center", fontFamily: theme.mono, fontSize: 22, color: theme.ask, ...rise(frame, 6.4, 16) }}>{copy.flowFallback}</div>
    </AbsoluteFill>
  )
}

const Outcome: React.FC<{ at: P; label: string; verdict: Verdict; on: boolean; start: number }> = ({ at, label, verdict, on, start }) => {
  const frame = useCurrentFrame()
  const color = theme[verdict]
  const r = rise(frame, start, 16)
  return (
    <div style={{ ...r, position: "absolute", left: at[0], top: at[1], minWidth: 180, height: 64, padding: "0 30px", borderRadius: 32, display: "flex", alignItems: "center", justifyContent: "center", whiteSpace: "nowrap", fontFamily: theme.sans, fontWeight: 800, fontSize: 22, letterSpacing: "0.08em", color: on ? "#FFFFFF" : color, background: on ? color : theme.card, border: `2px solid ${color}`, boxShadow: on ? `0 0 60px ${color}` : "none", transform: `translate(-50%, -50%) ${r.transform} scale(${on ? 1.08 : 1})` }}>
      {label}
    </div>
  )
}
