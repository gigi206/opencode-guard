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
```

The first render downloads a headless Chrome. Node 18 or later is needed.

## What to edit

| To change | Edit |
|---|---|
| Texts (both languages) | `src/content.ts`, `COPY.en` / `COPY.fr` |
| Order or length of the scenes, transitions | `src/content.ts`, `SCENES` (seconds; the total length follows) |
| Commands, rules and reasons shown, `guard` outputs, config snippet | `src/content.ts` (`DEMO_STEPS`, `CLI_TAKES`, `INSTALL_SNIPPET`…) |
| Colors, fonts | `src/theme.ts` (`theme` for the page, `term` for the dark windows) |
| Background music | put the file in `public/`, set `MUSIC` in `src/content.ts` |
| Logo at the end | `public/linagora.svg`, `BRAND_LOGO` in `src/content.ts` |
| Real OpenCode screenshots | put PNGs in `public/screenshots/`, set `SCREENSHOTS` in `src/content.ts` |
| The animation of one scene | `src/scenes/<Scene>.tsx` (times in seconds from the start of the scene) |

The rules, reasons and `guard` outputs are those the plugin really prints (`guard rules`, `guard last`, `guard show`, the log lines of the hooks).

## Scenes

1. `hook` — "Your AI agent has a shell", dangerous commands drifting behind
2. `danger` — `rm -rf ~`, red glitch: "One bad command is enough"
3. `reveal` — logo and tagline
4. `flow` — tool call → local rules → decision model (Nox-4B on the LINAGORA AI gateway) → allow / ask / deny
5. `demo` — three tool calls in OpenCode: deny, ask, deny (exfiltration)
6. `redaction` — a key in a prompt is replaced by its placeholder before reaching the provider
7. `selfProtection` — the agent tries to remove the plugin from `opencode.json`
8. `cli` — `guard rules`, `guard last`, `guard allow … && guard show`
9. `stats` — 62 rules, 0 runtime dependencies, 0 build step, MIT
10. `outro` — "Not a sandbox. A guardrail.", the `opencode.json` entry, the repository

## License

Remotion is free for individuals and companies of up to 3 employees; larger companies need a [company license](https://www.remotion.dev/license) to render with it.
