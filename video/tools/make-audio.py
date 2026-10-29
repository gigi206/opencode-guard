#!/usr/bin/env python3
"""Synthesizes the music bed and the sound effects of the video (no sample, no third-party audio: no rights issue).

    python3 tools/make-audio.py            # writes public/audio/music.mp3 and public/audio/sfx/*.wav

Needs numpy and scipy. The music is 120 BPM (one bar = 2 s), in A minor; its sections are listed in SECTIONS below,
in bars. Sound effects are placed by the video itself (`SFX` in src/content.ts), so they follow scene edits.
"""
import os
import shutil
import subprocess
import wave

import numpy as np
from scipy import signal

SR = 44100
BPM = 120
BEAT = 60 / BPM
BAR = 4 * BEAT
LENGTH = 70.0  # seconds (the video is ~68 s; the end fades out in the video)
OUT = os.path.join(os.path.dirname(__file__), "..", "public", "audio")
rng = np.random.default_rng(7)

# Sections, in bars: what plays when.
SECTIONS = {
    "intro": (0, 4),  # pad and pulse, riser into the drop
    "drop": (4, 16),  # full groove (reveal, flow, demo)
    "break": (16, 18),  # no kick (redaction)
    "groove": (18, 28),  # full groove (self-protection, CLI)
    "build": (28, 30),  # snare roll and riser (stats)
    "outro": (30, 35),  # final hit, pad and arpeggio fading
}
CHORDS = [  # one per bar, repeated: Am, F, C, G (MIDI notes)
    [57, 60, 64, 69],
    [53, 57, 60, 65],
    [48, 55, 60, 64],
    [55, 59, 62, 67],
]
BASS = [45, 41, 36, 43]


def hz(note):
    return 440.0 * 2 ** ((note - 69) / 12)


def t_of(n):
    return np.arange(n) / SR


def saw(freq, n, phase=0.0):
    return 2 * ((t_of(n) * freq + phase) % 1.0) - 1


def lowpass(x, cutoff, order=2):
    b, a = signal.butter(order, min(cutoff, SR / 2 - 100) / (SR / 2), "low")
    return signal.lfilter(b, a, x)


def highpass(x, cutoff, order=2):
    b, a = signal.butter(order, cutoff / (SR / 2), "high")
    return signal.lfilter(b, a, x)


def bandpass(x, lo, hi, order=2):
    b, a = signal.butter(order, [lo / (SR / 2), hi / (SR / 2)], "band")
    return signal.lfilter(b, a, x)


def env(n, attack, release, sustain_end=None):
    """Linear attack, then exponential-ish decay to 0 at the end of n samples."""
    e = np.ones(n)
    a = max(1, int(attack * SR))
    e[:a] = np.linspace(0, 1, a)
    r = max(1, int(release * SR))
    e[-r:] *= np.linspace(1, 0, r) ** 2
    return e


def decay(n, seconds):
    return np.exp(-t_of(n) / seconds)


def place(buf, sound, at):
    i = int(at * SR)
    if i >= len(buf):
        return
    end = min(len(buf), i + len(sound))
    buf[i:end] += sound[: end - i]


def reverb(x, seconds=2.2, mix=0.25):
    n = int(seconds * SR)
    ir = rng.standard_normal(n) * np.exp(-t_of(n) / (seconds / 5))
    ir = lowpass(ir, 6000)
    wet = signal.fftconvolve(x, ir)[: len(x)]
    wet /= np.max(np.abs(wet)) + 1e-9
    return x + mix * wet * np.max(np.abs(x))


# ── Instruments ──────────────────────────────────────────────────────────────────────────────


def kick(length=0.45):
    n = int(length * SR)
    t = t_of(n)
    f = 45 + 110 * np.exp(-t / 0.04)
    body = np.sin(2 * np.pi * np.cumsum(f) / SR) * np.exp(-t / 0.18)
    click = highpass(rng.standard_normal(n), 3000) * np.exp(-t / 0.004) * 0.3
    return np.tanh(1.6 * (body + click))


def clap():
    n = int(0.35 * SR)
    noise = bandpass(rng.standard_normal(n), 900, 3500)
    e = np.zeros(n)
    for k, d in enumerate([0, 0.012, 0.024]):
        i = int(d * SR)
        e[i:] += np.exp(-t_of(n - i) / (0.012 if k < 2 else 0.12))
    return noise * e * 0.6


def hat(open_=False):
    n = int((0.25 if open_ else 0.06) * SR)
    return highpass(rng.standard_normal(n), 7500) * decay(n, 0.08 if open_ else 0.015) * 0.35


def pad(notes, length):
    n = int(length * SR)
    out = np.zeros(n)
    for note in notes:
        for detune in (-0.12, -0.05, 0.0, 0.05, 0.12):
            out += saw(hz(note) * 2 ** (detune / 12), n, rng.random())
    out = lowpass(out / (len(notes) * 5), 1500)
    return out * env(n, 0.35, 0.6)


def bass_note(note, length):
    n = int(length * SR)
    t = t_of(n)
    x = saw(hz(note), n) * 0.6 + np.sin(2 * np.pi * hz(note) * t) * 0.8
    cutoff_env = 250 + 900 * np.exp(-t / 0.08)
    # Filter in two halves (cheap approximation of an envelope-controlled filter).
    half = n // 3
    y = np.concatenate([lowpass(x[:half], cutoff_env[0]), lowpass(x[half:], cutoff_env[half])])
    return y * env(n, 0.004, 0.05)


def pluck(note, length=0.3):
    n = int(length * SR)
    x = saw(hz(note), n) + 0.5 * saw(hz(note) * 2.003, n)
    return lowpass(x, 3200) * decay(n, 0.09) * 0.25


def riser(length):
    n = int(length * SR)
    t = t_of(n)
    noise = rng.standard_normal(n)
    out = np.zeros(n)
    chunks = 24
    for c in range(chunks):
        a, b = c * n // chunks, (c + 1) * n // chunks
        lo = 400 + 7000 * (c / chunks) ** 2
        out[a:b] = bandpass(noise[a:b], lo, min(lo * 2.2, 18000))
    tone = np.sin(2 * np.pi * np.cumsum(200 + 1200 * (t / length) ** 2) / SR) * 0.15
    return (out * 0.5 + tone) * (t / length) ** 1.5


def impact(length=2.5):
    n = int(length * SR)
    t = t_of(n)
    boom = np.sin(2 * np.pi * np.cumsum(30 + 80 * np.exp(-t / 0.08)) / SR) * np.exp(-t / 0.7)
    noise = lowpass(rng.standard_normal(n), 2500) * np.exp(-t / 0.25) * 0.5
    return reverb(np.tanh(1.5 * (boom + noise)), 2.0, 0.3)


# ── Music ────────────────────────────────────────────────────────────────────────────────────


def in_section(bar, *names):
    return any(SECTIONS[name][0] <= bar < SECTIONS[name][1] for name in names)


def music():
    n = int(LENGTH * SR)
    drums, bass, pads, plucks, fx = (np.zeros(n) for _ in range(5))
    sidechain = np.ones(n)
    k, c = kick(), clap()
    bars = int(LENGTH / BAR) + 1
    for bar in range(bars):
        t0 = bar * BAR
        chord = CHORDS[bar % 4]
        groove = in_section(bar, "drop", "groove", "build")
        # Pad every bar, except the last bars of the outro (it rings out from the final hit).
        if bar < SECTIONS["outro"][0] + 3:
            place(pads, pad(chord, BAR + 0.6), t0)
        # Kick (4/4) with side-chain ducking.
        if groove:
            for beat in range(4):
                at = t0 + beat * BEAT
                place(drums, k, at)
                i = int(at * SR)
                duck = 1 - 0.7 * np.exp(-t_of(int(0.25 * SR)) / 0.08)
                sidechain[i : i + len(duck)] = np.minimum(sidechain[i : i + len(duck)], duck[: n - i])
        # Clap on 2 and 4.
        if groove and not in_section(bar, "build"):
            for beat in (1, 3):
                place(drums, c, t0 + beat * BEAT)
        # Hats: 16ths quiet in the intro, offbeat 8ths and open hats in the groove.
        if bar >= 2 and bar < SECTIONS["outro"][0]:
            for s16 in range(16):
                at = t0 + s16 * BEAT / 4
                if groove:
                    if s16 % 4 == 2:
                        place(drums, hat(open_=s16 == 14), at)
                    elif s16 % 2 == 1:
                        place(drums, hat() * 0.5, at)
                else:
                    place(drums, hat() * (0.25 + 0.15 * (s16 % 2 == 0)), at)
        # Snare roll during the build.
        if in_section(bar, "build"):
            steps = 8 if bar == SECTIONS["build"][0] else 16
            for i in range(steps):
                place(drums, c * (0.4 + 0.6 * i / steps), t0 + i * BAR / steps)
        # Bass: 8ths on the root in the groove, a soft pulse in the intro.
        if groove or in_section(bar, "intro", "break"):
            root = BASS[bar % 4]
            for e8 in range(8):
                note = root + (12 if groove and e8 in (3, 7) else 0)
                level = 1.0 if groove else 0.45
                place(bass, bass_note(note, BEAT / 2 * 0.9) * level, t0 + e8 * BEAT / 2)
        # Arpeggio in 16ths from the drop on, and in the outro.
        if bar >= SECTIONS["drop"][0]:
            tones = chord + [chord[1] + 12, chord[2] + 12]
            pattern = [0, 2, 3, 1, 4, 3, 2, 5]
            for s16 in range(16):
                level = 1.0 if not in_section(bar, "outro") else max(0.0, 1 - (bar - SECTIONS["outro"][0]) / 4)
                place(plucks, pluck(tones[pattern[s16 % 8]] + 12) * level, t0 + s16 * BEAT / 4)
    # Risers into the drop, after the break, into the outro; impacts on the downbeats.
    place(fx, riser(BAR * 2) * 0.5, SECTIONS["drop"][0] * BAR - BAR * 2)
    place(fx, riser(BAR) * 0.4, SECTIONS["groove"][0] * BAR - BAR)
    place(fx, riser(BAR * 2) * 0.6, SECTIONS["outro"][0] * BAR - BAR * 2)
    for bar in (SECTIONS["drop"][0], SECTIONS["outro"][0]):
        place(fx, impact() * 0.7, bar * BAR)

    # Delay on the arpeggio (dotted eighth), stereo.
    d = int(BEAT * 0.75 * SR)
    left, right = plucks.copy(), plucks.copy()
    for k_ in range(1, 4):
        left[d * k_ :] += plucks[: -d * k_] * (0.45**k_) * (k_ % 2)
        right[d * k_ :] += plucks[: -d * k_] * (0.45**k_) * ((k_ + 1) % 2)
    pads_r = reverb(pads * sidechain, 3.0, 0.35)
    mix_l = drums * 0.9 + bass * sidechain * 0.55 + pads_r * 0.35 + left * 0.5 + fx * 0.6
    mix_r = drums * 0.9 + bass * sidechain * 0.55 + np.roll(pads_r, 300) * 0.35 + right * 0.5 + fx * 0.6
    stereo = np.stack([mix_l, mix_r], axis=1)
    # Fade in the first beat, fade out the last 3 seconds.
    fade = np.ones(n)
    fade[: int(0.3 * SR)] = np.linspace(0, 1, int(0.3 * SR))
    fade[-int(3 * SR) :] = np.linspace(1, 0, int(3 * SR)) ** 2
    return master(stereo * fade[:, None])


# ── Sound effects ────────────────────────────────────────────────────────────────────────────


def whoosh(length=0.7):
    n = int(length * SR)
    t = t_of(n)
    noise = rng.standard_normal(n)
    out = np.zeros(n)
    chunks = 20
    for c in range(chunks):
        a, b = c * n // chunks, (c + 1) * n // chunks
        x = c / chunks
        centre = 500 + 4500 * np.sin(np.pi * x)
        out[a:b] = bandpass(noise[a:b], centre * 0.6, centre * 1.6)
    return out * np.sin(np.pi * t / length) ** 2 * 0.6


def stamp_deny():
    n = int(0.6 * SR)
    t = t_of(n)
    thud = np.sin(2 * np.pi * np.cumsum(60 + 120 * np.exp(-t / 0.03)) / SR) * np.exp(-t / 0.12)
    buzz = lowpass(np.sign(np.sin(2 * np.pi * 110 * t)), 1800) * np.exp(-t / 0.09) * 0.35
    return np.tanh(2 * (thud + buzz)) * 0.8


def stamp_ask():
    n = int(0.9 * SR)
    t = t_of(n)
    tone = lambda f, delay: np.where(t >= delay, np.sin(2 * np.pi * f * (t - delay)) * np.exp(-np.maximum(t - delay, 0) / 0.25), 0)
    return reverb((tone(hz(76), 0) + tone(hz(81), 0.09)) * 0.35, 1.2, 0.3)


def pop():
    n = int(0.15 * SR)
    t = t_of(n)
    return np.sin(2 * np.pi * np.cumsum(500 + 900 * np.exp(-t / 0.015)) / SR) * np.exp(-t / 0.03) * 0.45


def scan():
    n = int(0.9 * SR)
    t = t_of(n)
    sweep = np.sin(2 * np.pi * np.cumsum(600 + 3000 * (t / 0.9) ** 1.5) / SR)
    shimmer = highpass(rng.standard_normal(n), 6000) * 0.15
    return reverb((sweep * 0.25 + shimmer) * np.sin(np.pi * t / 0.9), 0.8, 0.25)


def glitch():
    n = int(0.45 * SR)
    t = t_of(n)
    out = np.zeros(n)
    i = 0
    while i < n:
        length = int(rng.uniform(0.01, 0.04) * SR)
        f = rng.choice([80, 160, 320, 640, 1280])
        seg = np.sign(np.sin(2 * np.pi * f * t_of(length))) * rng.uniform(0.3, 0.8)
        out[i : i + length] = seg[: n - i]
        i += length + int(rng.uniform(0, 0.015) * SR)
    return lowpass(out, 5000) * np.exp(-t / 0.3) * 0.5


def master(x):
    x = np.tanh(1.2 * x)
    return x / (np.max(np.abs(x)) + 1e-9) * 0.89


def write(path, x):
    if x.ndim == 1:
        x = np.stack([x, x], axis=1)
    data = (np.clip(x, -1, 1) * 32767).astype("<i2")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with wave.open(path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(data.tobytes())
    print("wrote", os.path.relpath(path))


if __name__ == "__main__":
    wav = os.path.join(OUT, "music.wav")
    write(wav, music())
    # Compressed with ffmpeg when it is there (12 MB → 2 MB); content.ts points to the mp3.
    if shutil.which("ffmpeg"):
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", wav, "-b:a", "256k", wav[:-4] + ".mp3"], check=True)
        os.remove(wav)
        print("wrote", os.path.relpath(wav[:-4] + ".mp3"))
    for name, make in {
        "whoosh": whoosh,
        "impact": lambda: impact(2.0),
        "stamp-deny": stamp_deny,
        "stamp-ask": stamp_ask,
        "pop": pop,
        "scan": scan,
        "glitch": glitch,
    }.items():
        write(os.path.join(OUT, "sfx", f"{name}.wav"), master(make()) * 0.9)
