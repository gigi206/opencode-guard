// The whole video: the scenes of content.ts in order, joined by transitions, over the animated background.
import { TransitionSeries, linearTiming, type TransitionPresentation } from "@remotion/transitions"
import { fade } from "@remotion/transitions/fade"
import { slide } from "@remotion/transitions/slide"
import { wipe } from "@remotion/transitions/wipe"
import { Fragment, useEffect, useState } from "react"
import { AbsoluteFill, Audio, continueRender, delayRender, interpolate, staticFile, useCurrentFrame, useVideoConfig } from "remotion"
import { s } from "./anim"
import { COPY, MUSIC, MUSIC_VOLUME, SCENES, TRANSITION, type Copy, type SceneId, type TransitionKind } from "./content"
import { Background } from "./components/Background"
import { gradient } from "./theme"
import { Cli } from "./scenes/Cli"
import { Danger } from "./scenes/Danger"
import { Demo } from "./scenes/Demo"
import { Flow } from "./scenes/Flow"
import { Hook } from "./scenes/Hook"
import { Outro } from "./scenes/Outro"
import { Redaction } from "./scenes/Redaction"
import { Reveal } from "./scenes/Reveal"
import { SelfProtection } from "./scenes/SelfProtection"
import { Stats } from "./scenes/Stats"

const SCENE_COMPONENTS: Record<SceneId, React.FC<{ copy: Copy }>> = {
  hook: Hook,
  danger: Danger,
  reveal: Reveal,
  flow: Flow,
  demo: Demo,
  redaction: Redaction,
  selfProtection: SelfProtection,
  cli: Cli,
  stats: Stats,
  outro: Outro,
}

const presentation = (kind: TransitionKind): TransitionPresentation<any> =>
  kind === "slide" ? slide({ direction: "from-right" }) : kind === "wipe" ? wipe({ direction: "from-left" }) : fade()

/** Length of the video in frames: the scenes minus the overlap of each transition. */
export function totalFrames(): number {
  return SCENES.reduce((total, scene, i) => total + s(scene.seconds) - (i > 0 && scene.transition !== "none" ? s(TRANSITION) : 0), 0)
}

/** Waits for the fonts before the first frame is captured. */
function useFonts() {
  const [handle] = useState(() => delayRender("fonts"))
  useEffect(() => {
    const weights = ["400", "500", "600", "700", "800"].map((w) => `${w} 40px Inter`)
    Promise.all([...weights, "400 40px 'JetBrains Mono'", "700 40px 'JetBrains Mono'"].map((font) => document.fonts.load(font)))
      .then(() => continueRender(handle))
      .catch(() => continueRender(handle))
  }, [handle])
}

const ProgressBar: React.FC = () => {
  const frame = useCurrentFrame()
  const { durationInFrames } = useVideoConfig()
  const width = interpolate(frame, [0, durationInFrames - 1], [0, 100])
  return <div style={{ position: "absolute", left: 0, bottom: 0, height: 5, width: `${width}%`, backgroundImage: gradient, opacity: 0.8 }} />
}

export const Video: React.FC<{ lang: "en" | "fr" }> = ({ lang }) => {
  useFonts()
  const copy = COPY[lang]
  return (
    <AbsoluteFill>
      <Background />
      <TransitionSeries>
        {SCENES.map((scene, i) => {
          const Scene = SCENE_COMPONENTS[scene.id]
          const kind = scene.transition ?? "fade"
          return (
            <Fragment key={scene.id}>
              {i > 0 && kind !== "none" && <TransitionSeries.Transition presentation={presentation(kind)} timing={linearTiming({ durationInFrames: s(TRANSITION) })} />}
              <TransitionSeries.Sequence durationInFrames={s(scene.seconds)} name={scene.id}>
                <Scene copy={copy} />
              </TransitionSeries.Sequence>
            </Fragment>
          )
        })}
      </TransitionSeries>
      <ProgressBar />
      {MUSIC && <Audio src={staticFile(MUSIC)} volume={MUSIC_VOLUME} />}
    </AbsoluteFill>
  )
}
