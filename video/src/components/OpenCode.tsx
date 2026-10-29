// A real OpenCode screenshot, animated, and the drawn mock-up of a session used when no screenshot is set in
// content.ts.
import { Img, staticFile, useCurrentFrame } from "remotion"
import { pop, progress, s, typed, typedEnd } from "../anim"
import type { Shot } from "../content"
import { term, theme, type Verdict } from "../theme"
import { Window } from "./Terminal"

export interface Outcome {
  verdict: Verdict
  rule: string
  reason: string
}

const W = 1120

/** The window with a user prompt, the tool call typed by the agent, then the guard's outcome. */
export const OpenCodeSession: React.FC<{
  prompt: string
  tool: string
  command: string
  outcome: Outcome
  labels: { askPrompt: string; askButtons: [string, string, string]; blocked: string }
  start?: number
  chosen?: number
}> = ({ prompt, tool, command, outcome, labels, start = 0, chosen = 0 }) => {
  const frame = useCurrentFrame()
  const promptIn = progress(frame, start, 0.4)
  const callStart = start + 0.5
  const shown = typed(frame, command, callStart + 0.2, 40)
  const outcomeAt = typedEnd(command, callStart + 0.2, 40) + 0.3
  const o = pop(frame, outcomeAt, 14)
  const color = theme[outcome.verdict]
  const pressed = frame > s(outcomeAt + 1.6)
  return (
    <Window title="opencode — ~/projects/my-app" width={W}>
      <div style={{ position: "relative", height: 470, fontFamily: theme.mono, fontSize: 21, color: term.text, padding: "28px 34px" }}>
        {/* User message */}
        <div style={{ opacity: promptIn, borderLeft: `4px solid ${term.accent}`, padding: "10px 18px", background: "rgba(255,90,102,0.08)", borderRadius: 6 }}>
          {prompt}
        </div>
        {/* Tool call */}
        <div style={{ opacity: progress(frame, callStart, 0.3), marginTop: 26, display: "flex", gap: 14, alignItems: "baseline", whiteSpace: "pre" }}>
          <span style={{ color: term.muted }}>⚙</span>
          <span style={{ color: term.muted, fontWeight: 700 }}>{tool}</span>
          <span>
            <span style={{ color: term.allow }}>$ </span>
            {shown}
          </span>
        </div>
        {/* Outcome */}
        {outcome.verdict === "deny" ? (
          <div style={{ marginTop: 26, opacity: Math.min(1, o * 1.4), transform: `translateY(${(1 - o) * 20}px)`, border: `2px solid ${color}`, background: `${color}14`, borderRadius: 10, padding: "16px 20px", boxShadow: `0 0 50px ${color}33` }}>
            <div style={{ color, fontWeight: 700 }}>✕ [guard] {labels.blocked} (rule {outcome.rule})</div>
            <div style={{ color: term.text, marginTop: 6, opacity: 0.9 }}>{outcome.reason}</div>
          </div>
        ) : (
          <div style={{ marginTop: 26, opacity: Math.min(1, o * 1.4), transform: `translateY(${(1 - o) * 20}px)`, border: `2px solid ${color}`, background: `${color}10`, borderRadius: 10, padding: "18px 22px", boxShadow: `0 0 50px ${color}2A` }}>
            <div style={{ color, fontWeight: 700 }}>△ {labels.askPrompt}</div>
            <div style={{ marginTop: 8 }}>
              <span style={{ color: term.muted }}>guard · </span>
              <span style={{ fontWeight: 700 }}>{outcome.rule}</span>
              <span style={{ color: term.muted }}>: </span>
              {outcome.reason}
            </div>
            <div style={{ display: "flex", gap: 14, marginTop: 18 }}>
              {labels.askButtons.map((label, i) => {
                const active = i === chosen
                return (
                  <div key={label} style={{ padding: "8px 16px", borderRadius: 6, fontSize: 18, background: active ? (pressed ? color : `${color}33`) : "rgba(255,255,255,0.06)", color: active && pressed ? term.bg : term.text, fontWeight: active ? 700 : 400, transition: "none" }}>
                    {label}
                  </div>
                )
              })}
            </div>
          </div>
        )}
        {/* Input bar */}
        <div style={{ position: "absolute", left: 34, right: 34, bottom: 26, border: `1px solid ${term.border}`, borderRadius: 10, padding: "14px 18px", display: "flex", justifyContent: "space-between", color: term.muted, fontSize: 18 }}>
          <span>
            <span style={{ color: term.link, fontWeight: 700 }}>Build</span> · my-app
          </span>
          <span>guard ● active</span>
        </div>
      </div>
    </Window>
  )
}

/**
 * A real screenshot from `public/screenshots/<dir>/`, in the same window chrome: it is revealed top to bottom from
 * `start`, then the camera pushes in on `focus` at `zoomAt` (seconds), when the verdict appears.
 */
export const Screenshot: React.FC<{ dir: string; shot: Shot; start?: number; zoomAt?: number }> = ({ dir, shot, start = 0, zoomAt = 1.2 }) => {
  const frame = useCurrentFrame()
  const reveal = progress(frame, start, 0.7)
  const zoom = 1 + 0.13 * progress(frame, zoomAt, 0.9) + 0.03 * progress(frame, start, 4)
  const [fx, fy] = shot.focus
  return (
    <Window title="opencode — ~/projects/my-app" width={W}>
      <div style={{ overflow: "hidden", background: "#0a0a0a" }}>
        <Img
          src={staticFile(`screenshots/${dir}/${shot.file}`)}
          style={{ width: "100%", display: "block", transform: `scale(${zoom})`, transformOrigin: `${fx * 100}% ${fy * 100}%`, clipPath: `inset(0 0 ${(1 - reveal) * 100}% 0)` }}
        />
      </div>
    </Window>
  )
}
