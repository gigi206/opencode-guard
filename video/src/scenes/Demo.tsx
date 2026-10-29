// 5. Three tool calls in an OpenCode session: deny, ask, deny (exfiltration). One "cut" per step.
import { AbsoluteFill, Sequence, useCurrentFrame } from "remotion"
import { fadeOut, progress, rise, s } from "../anim"
import { DEMO_STEPS, type Copy } from "../content"
import { theme } from "../theme"
import { OpenCodeSession, Screenshot } from "../components/OpenCode"
import { VerdictBadge } from "../components/Verdict"
import { Eyebrow } from "../components/Title"

const FIRST = 0.3
const STEP = 4.4
const SHOT_VERDICT = 1.2

export const Demo: React.FC<{ copy: Copy }> = ({ copy }) => (
  <AbsoluteFill>
    <div style={{ position: "absolute", top: 70, left: 120 }}>
      <Eyebrow text={copy.demoTitle} start={0} />
    </div>
    {DEMO_STEPS.map((step, i) => (
      <Sequence key={i} from={s(FIRST + i * STEP)} durationInFrames={s(STEP)} layout="none">
        <Step index={i} copy={copy} last={i === DEMO_STEPS.length - 1} />
      </Sequence>
    ))}
  </AbsoluteFill>
)

const Step: React.FC<{ index: number; copy: Copy; last: boolean }> = ({ index, copy, last }) => {
  const frame = useCurrentFrame()
  const step = DEMO_STEPS[index]!
  const enter = progress(frame, 0, 0.5)
  const exit = last ? 1 : fadeOut(frame, STEP, 0.35)
  // When the verdict shows: the screenshot zooms in on it, or the mock-up has typed the command.
  const outcomeAt = step.screenshot ? SHOT_VERDICT : 0.7 + step.command.length / 40 + 0.3
  return (
    <AbsoluteFill style={{ opacity: Math.min(enter, exit), flexDirection: "row", alignItems: "center", padding: "0 120px", gap: 80 }}>
      <div style={{ width: 520, transform: `translateX(${(1 - enter) * -60}px)` }}>
        <div style={{ fontFamily: theme.mono, fontSize: 120, fontWeight: 700, color: "rgba(30,33,37,0.08)", lineHeight: 1 }}>0{index + 1}</div>
        <div style={{ fontFamily: theme.sans, fontSize: 64, fontWeight: 800, letterSpacing: "-0.03em", color: theme.text, lineHeight: 1.1, marginTop: 10, ...rise(frame, 0.15) }}>{copy.demoCaptions[index]}</div>
        <div style={{ marginTop: 40, height: 70 }}>
          <VerdictBadge verdict={step.verdict} label={copy.verdicts[step.verdict]} start={outcomeAt + 0.15} />
        </div>
        <div style={{ marginTop: 22, fontFamily: theme.mono, fontSize: 24, color: theme.muted, ...rise(frame, outcomeAt + 0.4, 12) }}>
          rule <span style={{ color: theme.text }}>{step.rule}</span>
        </div>
      </div>
      <div style={{ transform: `translateX(${(1 - enter) * 80}px) perspective(1600px) rotateY(${(1 - enter) * -8}deg)` }}>
        {step.screenshot ? (
          <Screenshot dir={copy.screenshotDir} shot={step.screenshot} start={0.1} zoomAt={SHOT_VERDICT} />
        ) : (
          <OpenCodeSession
            prompt={copy.demoPrompts[index]!}
            tool={step.tool}
            command={step.command}
            outcome={step}
            labels={copy}
            start={0.1}
          />
        )}
      </div>
    </AbsoluteFill>
  )
}
