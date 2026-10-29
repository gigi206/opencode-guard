// 6. A secret typed in a prompt is scanned and replaced by a placeholder before it reaches the provider.
import { AbsoluteFill, interpolate, random, useCurrentFrame } from "remotion"
import { clamp, progress, rise, s, typed, typedEnd } from "../anim"
import { REDACTION, type Copy } from "../content"
import { cardShadow, theme } from "../theme"
import { Words } from "../components/Title"

const TYPE_AT = 0.6
const SCAN_AT = 2.5
const SEND_AT = 3.6
const GLYPHS = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789#$%&*"

const Card: React.FC<{ label: string; children: React.ReactNode; color: string; style?: React.CSSProperties }> = ({ label, children, color, style }) => (
  <div style={{ width: 720, borderRadius: 22, border: `2px solid ${color}55`, background: theme.card, padding: "26px 32px", boxShadow: `${cardShadow}, 0 0 60px ${color}1A`, ...style }}>
    <div style={{ fontFamily: theme.sans, fontSize: 22, fontWeight: 600, color, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 16 }}>{label}</div>
    <div style={{ fontFamily: theme.mono, fontSize: 25, lineHeight: 1.6, color: theme.text, minHeight: 130 }}>{children}</div>
  </div>
)

export const Redaction: React.FC<{ copy: Copy }> = ({ copy }) => {
  const frame = useCurrentFrame()
  const before = `${copy.redactionPrompt} ${REDACTION.secret}`
  const prefix = `${copy.redactionPrompt} `
  const shown = typed(frame, before, TYPE_AT, 40)
  const scan = interpolate(frame, [s(SCAN_AT), s(SCAN_AT + 0.7)], [0, 1], clamp)
  const scrambling = frame >= s(SCAN_AT) && frame < s(SCAN_AT + 0.7)
  const redacted = frame >= s(SCAN_AT + 0.7)
  const scrambled = REDACTION.secret
    .split("")
    .map((c, i) => (i / REDACTION.secret.length < scan ? GLYPHS[Math.floor(random(`${i}-${frame}`) * GLYPHS.length)] : c))
    .join("")
  const travel = progress(frame, SEND_AT, 0.9)
  const received = progress(frame, SEND_AT + 0.8, 0.5)
  const done = frame >= s(typedEnd(before, TYPE_AT, 40))

  const secretPart = redacted ? (
    <span style={{ color: theme.redacted, background: `${theme.redacted}1A`, borderRadius: 6, padding: "0 4px", whiteSpace: "nowrap" }}>{REDACTION.placeholder}</span>
  ) : (
    <span style={{ color: scrambling ? theme.ask : theme.deny, wordBreak: "break-all" }}>{scrambling ? scrambled : shown.slice(prefix.length)}</span>
  )

  return (
    <AbsoluteFill>
      <div style={{ position: "absolute", top: 110, width: "100%", textAlign: "center" }}>
        <Words text={copy.redactionTitle} start={0} size={76} />
        <div style={{ marginTop: 20, fontFamily: theme.sans, fontSize: 30, color: theme.muted, ...rise(frame, 0.4, 16) }}>{copy.redactionSub}</div>
      </div>
      <AbsoluteFill style={{ flexDirection: "row", justifyContent: "center", alignItems: "center", gap: 120, paddingTop: 150 }}>
        <div style={{ position: "relative", ...rise(frame, 0.3, 30) }}>
          <Card label={copy.redactionYou} color={theme.accent}>
            {shown.slice(0, prefix.length)}
            {shown.length > prefix.length && secretPart}
            {!done && <span style={{ background: theme.text }}>&nbsp;</span>}
          </Card>
          {scan > 0 && scan < 1 && (
            <div style={{ position: "absolute", top: 0, bottom: 0, left: `${scan * 100}%`, width: 4, background: theme.redacted, boxShadow: `0 0 40px 12px ${theme.redacted}` }} />
          )}
        </div>
        {/* Packet travelling to the provider */}
        <div style={{ position: "absolute", left: 960 - 60 + (travel - 0.5) * 160, top: 600, width: 120, height: 6, borderRadius: 3, background: theme.redacted, opacity: travel > 0 && travel < 1 ? 1 : 0, boxShadow: `0 0 30px ${theme.redacted}` }} />
        <div style={{ ...rise(frame, 0.5, 30) }}>
          <Card label={copy.redactionProvider} color={theme.redacted}>
            <span style={{ opacity: received }}>
              {prefix}
              <span style={{ color: theme.redacted, whiteSpace: "nowrap" }}>{REDACTION.placeholder}</span>
            </span>
          </Card>
        </div>
      </AbsoluteFill>
    </AbsoluteFill>
  )
}
