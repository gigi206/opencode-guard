// 10. "Not a sandbox. A guardrail." then how to install and where to find it.
import { AbsoluteFill, Img, staticFile, useCurrentFrame } from "remotion"
import { rise } from "../anim"
import { BRAND_LOGO, INSTALL_SNIPPET, REPO_URL, type Copy } from "../content"
import { gradientText, term, theme } from "../theme"
import { Shield } from "../components/Shield"
import { TerminalLine, Window } from "../components/Terminal"
import { Words } from "../components/Title"

export const Outro: React.FC<{ copy: Copy }> = ({ copy }) => {
  const frame = useCurrentFrame()
  return (
    <AbsoluteFill style={{ flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 110 }}>
      <div>
        <Shield size={120} start={0} />
        <Words text={copy.outroLine1} start={0.3} size={96} color={theme.muted} style={{ marginTop: 30 }} />
        <Words text={copy.outroLine2} start={0.7} size={110} wordStyle={() => gradientText} />
        <div style={{ marginTop: 50, display: "flex", alignItems: "center", gap: 18, fontFamily: theme.mono, fontSize: 34, color: theme.text, ...rise(frame, 1.6, 16) }}>
          <svg width={40} height={40} viewBox="0 0 16 16" fill={theme.text}>
            <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
          </svg>
          {REPO_URL}
        </div>
        <div style={{ marginTop: 16, fontFamily: theme.sans, fontSize: 26, color: theme.muted, ...rise(frame, 1.9, 12) }}>{copy.outroPowered}</div>
        {BRAND_LOGO && <Img src={staticFile(BRAND_LOGO)} style={{ height: 64, marginTop: 44, ...rise(frame, 2.2, 12) }} />}
      </div>
      <div style={rise(frame, 1.1, 40)}>
        <div style={{ fontFamily: theme.sans, fontSize: 26, fontWeight: 600, color: theme.accent2, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 18 }}>{copy.outroCta}</div>
        <Window title="opencode.json" width={820}>
          <div style={{ padding: "26px 32px", fontFamily: theme.mono, fontSize: 21, lineHeight: 1.5, color: term.text }}>
            {INSTALL_SNIPPET.map((line, i) => (
              <div key={i} style={rise(frame, 1.3 + i * 0.05, 10)}>
                <TerminalLine line={line} />
              </div>
            ))}
          </div>
        </Window>
      </div>
    </AbsoluteFill>
  )
}
