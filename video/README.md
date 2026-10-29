# opencode-guard — presentation video

A ~68 s motion design video of the plugin and its `guard` command, in LINAGORA's colors, in English (`GuardEN`) and French (`GuardFR`). It is written as code with [Remotion](https://www.remotion.dev) (React): every frame is computed from a few files, so a text, a color or a timing is changed in one place and the video is rendered again.

This folder is separate from the plugin: its dependencies never reach the plugin, which stays dependency-free.

## Preview and render

```sh
cd video
npm install
npm run studio        # live preview with a timeline, reloads on save (http://localhost:3000)
npm run render        # out/opencode-guard-en.mp4
npm run render:fr     # out/opencode-guard-fr.mp4
npm run still         # out/poster.png (one frame, e.g. for a thumbnail)
npm run screenshots   # retake the OpenCode screenshots (see below)
npm run audio         # regenerate the music and sound effects (python3 with numpy and scipy; ffmpeg for the mp3)
```

The first render downloads a headless Chrome. Node 18 or later is needed.

## What to edit

| To change | Edit |
|---|---|
| Texts (both languages) | `src/content.ts`, `COPY.en` / `COPY.fr` |
| Order or length of the scenes, transitions | `src/content.ts`, `SCENES` (seconds; the total length follows) |
| Commands, rules and reasons shown, `guard` outputs, config snippet | `src/content.ts` (`DEMO_STEPS`, `CLI_TAKES`, `INSTALL_SNIPPET`…) |
| Colors, fonts | `src/theme.ts` (`theme` for the page, `term` for the dark windows) |
| Music | `MUSIC` in `src/content.ts` (any mp3/wav in `public/`; the default is synthesized by `tools/make-audio.py`) |
| Sound effects and when they play | `SFX` in `src/content.ts` (scene and seconds; they follow scene edits) |
| Logo at the end | `public/linagora.svg`, `BRAND_LOGO` in `src/content.ts` |
| OpenCode screenshots | `public/screenshots/<lang>/`, `SCREENSHOTS` in `src/content.ts` (`null`: a drawn window) |
| The animation of one scene | `src/scenes/<Scene>.tsx` (times in seconds from the start of the scene) |

The rules, reasons and `guard` outputs are those the plugin really prints (`guard rules`, `guard last`, `guard show`, the log lines of the hooks).

## Screenshots

The OpenCode screens are real: `tools/screenshots/capture.sh` installs OpenCode 2.2.0 in an isolated directory, loads this repository's plugin (with the LINAGORA gateway settings), and drives the TUI in tmux with a scripted local model (`mock-model.mjs`) that makes the agent run the demo commands. The guard really blocks or asks; each screen is rendered to a PNG with xterm.js. The prompts are in the script, in English and French; change them there and in `src/content.ts` together. It needs node, git and tmux.

## Audio

`tools/make-audio.py` synthesizes everything (no sample, so no rights issue): a 120 BPM music bed whose sections follow the scenes (`SECTIONS`, in bars of 2 s), and the sound effects (whoosh, impact, stamps, pop, scan, glitch). Replace `public/audio/music.mp3` or point `MUSIC` to another file to use a real track.

## Scenes

1. `hook` — "Your AI agent has a shell", dangerous commands drifting behind
2. `danger` — `rm -rf ~`, red glitch: "One bad command is enough"
3. `reveal` — logo and tagline
4. `flow` — tool call → local rules → decision model (Nox-4B on the LINAGORA AI gateway) → allow / ask / deny
5. `demo` — three tool calls in OpenCode (real screenshots): deny, ask, deny (exfiltration)
6. `redaction` — a key in a prompt is replaced by its placeholder before reaching the provider
7. `selfProtection` — the agent tries to remove the plugin from `opencode.json`
8. `cli` — `guard rules`, `guard last`, `guard allow … && guard show`
9. `stats` — 62 rules, 0 runtime dependencies, 0 build step, MIT
10. `outro` — "Not a sandbox. A guardrail.", `opencode plugin add github:gigi206/opencode-guard`, the `opencode.json` entry, the repository

## License

Remotion is free for individuals and companies of up to 3 employees; larger companies need a [company license](https://www.remotion.dev/license) to render with it.
