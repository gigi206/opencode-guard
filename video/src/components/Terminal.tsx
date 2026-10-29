// A terminal window: title bar, a typed command, then its output line by line.
import { useCurrentFrame } from "remotion"
import { progress, s, typed, typedEnd } from "../anim"
import type { Line, TermStyle } from "../content"
import { term, theme } from "../theme"

const STYLES: Record<TermStyle, React.CSSProperties> = {
  deny: { color: term.deny, fontWeight: 700 },
  ask: { color: term.ask },
  allow: { color: term.allow },
  model: { color: term.model },
  warn: { color: term.ask },
  dim: { color: term.muted },
  bold: { color: term.text, fontWeight: 700 },
  group: { color: term.link, fontWeight: 700 },
  prompt: { color: term.allow, fontWeight: 700 },
  bannerBlue: { background: "#3B5BDB", color: "#fff", fontWeight: 700 },
  bannerCyan: { background: "#0C8599", color: "#fff", fontWeight: 700 },
  bannerGreen: { background: "#2B8A3E", color: "#fff", fontWeight: 700 },
  lineBlue: { color: "#4C6EF5" },
  lineCyan: { color: "#15AABF" },
  lineGreen: { color: "#40C057" },
}

export const TerminalLine: React.FC<{ line: Line }> = ({ line }) => (
  <div style={{ whiteSpace: "pre", minHeight: "1.5em" }}>
    {line.map(([text, style], i) => (
      <span key={i} style={style ? STYLES[style] : undefined}>
        {text}
      </span>
    ))}
  </div>
)

export const Window: React.FC<{ title: string; width: number; children: React.ReactNode; style?: React.CSSProperties }> = ({ title, width, children, style }) => (
  <div
    style={{
      width,
      borderRadius: 18,
      background: term.bg,
      border: `1px solid ${term.border}`,
      boxShadow: "0 40px 100px rgba(30,33,37,0.28), 0 8px 20px rgba(30,33,37,0.12)",
      overflow: "hidden",
      backdropFilter: "blur(20px)",
      ...style,
    }}
  >
    <div style={{ height: 46, display: "flex", alignItems: "center", gap: 9, padding: "0 18px", borderBottom: `1px solid ${term.border}`, background: term.bar }}>
      {["#FF5F57", "#FEBC2E", "#28C840"].map((c) => (
        <div key={c} style={{ width: 13, height: 13, borderRadius: 7, background: c, opacity: 0.9 }} />
      ))}
      <div style={{ flex: 1, textAlign: "center", fontFamily: theme.sans, fontSize: 16, color: term.muted, marginRight: 60 }}>{title}</div>
    </div>
    {children}
  </div>
)

/**
 * The command is typed from `start` (seconds), then the output appears line by line, `lineDelay` apart.
 * The cursor blinks at the end of the command while it is being typed.
 */
export const Terminal: React.FC<{
  command: string
  output: Line[]
  start?: number
  lineDelay?: number
  width?: number
  fontSize?: number
  title?: string
  prompt?: string
}> = ({ command, output, start = 0, lineDelay = 0.045, width = 1240, fontSize = 21, title = "zsh — guard", prompt = "❯" }) => {
  const frame = useCurrentFrame()
  const shown = typed(frame, command, start, 32)
  const done = typedEnd(command, start, 32) + 0.25
  const cursorOn = Math.floor(frame / 15) % 2 === 0 || shown.length < command.length
  return (
    <Window title={title} width={width}>
      <div style={{ padding: "26px 32px 30px", fontFamily: theme.mono, fontSize, lineHeight: 1.5, color: term.text }}>
        <div style={{ whiteSpace: "pre" }}>
          <span style={{ color: term.allow, fontWeight: 700 }}>{prompt} </span>
          <span>{shown}</span>
          {frame < s(done) && <span style={{ opacity: cursorOn ? 1 : 0, background: term.text, marginLeft: 2 }}>&nbsp;</span>}
        </div>
        {output.map((line, i) => {
          const p = progress(frame, done + i * lineDelay, 0.25)
          return (
            <div key={i} style={{ opacity: p, transform: `translateX(${(1 - p) * -12}px)` }}>
              <TerminalLine line={line} />
            </div>
          )
        })}
      </div>
    </Window>
  )
}
