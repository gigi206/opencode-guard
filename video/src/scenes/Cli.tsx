// 8. The `guard` command: rules, latest decisions, then relaxing a rule and checking the settings in force.
import { AbsoluteFill, Sequence, useCurrentFrame } from "remotion"
import { fadeOut, progress, rise, s } from "../anim"
import { CLI_TAKES, type Copy } from "../content"
import { theme } from "../theme"
import { Terminal } from "../components/Terminal"
import { Eyebrow, Words } from "../components/Title"

const FIRST = 0.9
const TAKE = 4.35

export const Cli: React.FC<{ copy: Copy }> = ({ copy }) => (
  <AbsoluteFill>
    <div style={{ position: "absolute", top: 64, left: 120, right: 120, display: "flex", justifyContent: "space-between", alignItems: "flex-end" }}>
      <div>
        <Eyebrow text="bin/guard" start={0} />
        <Words text={copy.cliTitle} start={0.1} size={64} style={{ marginTop: 12 }} stagger={0.05} />
      </div>
    </div>
    {CLI_TAKES.map((take, i) => (
      <Sequence key={i} from={s(FIRST + i * TAKE)} durationInFrames={s(TAKE)} layout="none">
        <Take index={i} copy={copy} last={i === CLI_TAKES.length - 1} />
      </Sequence>
    ))}
  </AbsoluteFill>
)

const Take: React.FC<{ index: number; copy: Copy; last: boolean }> = ({ index, copy, last }) => {
  const frame = useCurrentFrame()
  const take = CLI_TAKES[index]!
  const enter = progress(frame, 0, 0.45)
  const exit = last ? 1 : fadeOut(frame, TAKE, 0.3)
  return (
    <AbsoluteFill style={{ opacity: Math.min(enter, exit), alignItems: "center", paddingTop: 250 }}>
      <div style={{ position: "relative", transform: `translateY(${(1 - enter) * 40}px) scale(${0.97 + 0.03 * enter})` }}>
        <Terminal command={take.command} output={take.output} start={0.15} width={1380} fontSize={19} lineDelay={0.04} />
        <div style={{ position: "absolute", right: -30, top: -34, padding: "12px 24px", borderRadius: 999, background: theme.accent, color: "#FFFFFF", fontFamily: theme.sans, fontWeight: 700, fontSize: 26, boxShadow: "0 16px 40px rgba(226,1,17,0.3)", ...rise(frame, 0.3, 16) }}>
          {copy.cliCaptions[index]}
        </div>
      </div>
    </AbsoluteFill>
  )
}
