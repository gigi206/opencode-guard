// Small animation helpers shared by the scenes. Times are in seconds, converted with the composition's fps.
import { Easing, interpolate, spring } from "remotion"
import { FPS } from "./content"

export const s = (seconds: number) => Math.round(seconds * FPS)

const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const

/** 0 → 1 between `start` and `start + duration` (seconds), eased. */
export function progress(frame: number, start: number, duration = 0.6, easing = Easing.bezier(0.16, 1, 0.3, 1)) {
  return interpolate(frame, [s(start), s(start + duration)], [0, 1], { ...clamp, easing })
}

/** A spring starting at `start` (seconds): pops slightly past 1 then settles. */
export function pop(frame: number, start: number, damping = 12) {
  return spring({ frame: frame - s(start), fps: FPS, config: { damping, mass: 0.6, stiffness: 140 } })
}

/** Style of an element rising into place while it un-blurs. */
export function rise(frame: number, start: number, distance = 40, duration = 0.7) {
  const p = progress(frame, start, duration)
  return {
    opacity: p,
    transform: `translateY(${(1 - p) * distance}px)`,
    filter: `blur(${(1 - p) * 12}px)`,
  }
}

/** Fade out over the last `duration` seconds before `end` (seconds). */
export function fadeOut(frame: number, end: number, duration = 0.4) {
  return 1 - progress(frame, end - duration, duration, Easing.in(Easing.cubic))
}

/** The first `count` characters of `text`, typed at `cps` characters per second from `start`. */
export function typed(frame: number, text: string, start: number, cps = 28) {
  const chars = Math.max(0, Math.floor(((frame - s(start)) / FPS) * cps))
  return text.slice(0, chars)
}

/** Time (seconds) when typing `text` at `cps` finishes. */
export const typedEnd = (text: string, start: number, cps = 28) => start + text.length / cps

export { clamp }
