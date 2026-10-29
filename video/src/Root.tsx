// The compositions listed in the studio: the same video in English and in French.
import { Composition } from "remotion"
import { FPS, HEIGHT, WIDTH } from "./content"
import { Video, totalFrames } from "./Video"

export const Root: React.FC = () => (
  <>
    <Composition id="GuardEN" component={Video} durationInFrames={totalFrames()} fps={FPS} width={WIDTH} height={HEIGHT} defaultProps={{ lang: "en" as const }} />
    <Composition id="GuardFR" component={Video} durationInFrames={totalFrames()} fps={FPS} width={WIDTH} height={HEIGHT} defaultProps={{ lang: "fr" as const }} />
  </>
)
