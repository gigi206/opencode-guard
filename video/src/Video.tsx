// The whole video: the scenes of content.ts in order, joined by transitions, over the animated background.
import { TransitionSeries, linearTiming, type TransitionPresentation } from "@remotion/transitions"
import { fade } from "@remotion/transitions/fade"
import { slide } from "@remotion/transitions/slide"
import { wipe } from "@remotion/transitions/wipe"
import { Fragment, useEffect, useState } from "react"
import { AbsoluteFill, Audio, Sequence, continueRender, delayRender, interpolate, staticFile, useCurrentFrame, useVideoConfig } from "remotion"
import { s } from "./anim"
import { COPY, MUSIC, MUSIC_VOLUME, SCENES, SFX, SFX_VOLUME, TRANSITION, TRANSITION_SFX, type Copy, type SceneId, type TransitionKind } from "./content"
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

/** First frame of each scene, as the transitions overlap them. */
function sceneStarts(): Record<SceneId, number> {
  const starts = {} as Record<SceneId, number>
  let frame = 0
  SCENES.forEach((scene, i) => {
    if (i > 0 && scene.transition !== "none") frame -= s(TRANSITION)
    starts[scene.id] = frame
    frame += s(scene.seconds)
  })
  return starts
}

/** The sound effects of content.ts, and a whoosh on every transition. */
const SoundEffects: React.FC = () => {
  if (SFX_VOLUME <= 0) return null
  const starts = sceneStarts()
  const cues = [
    ...SFX.filter((cue) => cue.scene in starts).map((cue) => ({ from: starts[cue.scene] + s(cue.at), sound: cue.sound, volume: cue.volume ?? 1 })),
    ...(TRANSITION_SFX ? SCENES.slice(1).filter((scene) => scene.transition !== "none").map((scene) => ({ from: starts[scene.id], sound: TRANSITION_SFX, volume: 0.5 })) : []),
  ]
  return (
    <>
      {cues.map((cue, i) => (
        <Sequence key={i} from={cue.from} layout="none" name={`sfx ${cue.sound}`}>
          <Audio src={staticFile(`audio/sfx/${cue.sound}.wav`)} volume={SFX_VOLUME * cue.volume} />
        </Sequence>
      ))}
    </>
  )
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

/** The music, faded out over the last 2 seconds of the video. */
const Music: React.FC<{ file: string }> = ({ file }) => {
  const { durationInFrames } = useVideoConfig()
  return <Audio src={staticFile(file)} volume={(f) => MUSIC_VOLUME * interpolate(f, [durationInFrames - s(2), durationInFrames], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" })} />
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
      {MUSIC && <Music file={MUSIC} />}
      <SoundEffects />
    </AbsoluteFill>
  )
}
