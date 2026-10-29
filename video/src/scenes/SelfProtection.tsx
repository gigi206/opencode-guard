// 7. The agent tries to remove the plugin from opencode.json: the guard asks first.
import { AbsoluteFill, useCurrentFrame } from "remotion"
import { progress, rise } from "../anim"
import { SELF_PROTECTION, type Copy } from "../content"
import { theme } from "../theme"
import { OpenCodeSession, Screenshot } from "../components/OpenCode"
import { Shield } from "../components/Shield"
import { Words } from "../components/Title"

export const SelfProtection: React.FC<{ copy: Copy }> = ({ copy }) => {
  const frame = useCurrentFrame()
  const enter = progress(frame, 0, 0.6)
  return (
    <AbsoluteFill style={{ flexDirection: "row", alignItems: "center", padding: "0 120px", gap: 80 }}>
      <div style={{ width: 560 }}>
        <Shield size={110} start={0} glow={false} />
        <Words text={copy.selfTitle} start={0.2} size={70} style={{ marginTop: 30 }} />
        <div style={{ marginTop: 28, fontFamily: theme.sans, fontSize: 30, lineHeight: 1.4, color: theme.muted, ...rise(frame, 0.7, 16) }}>{copy.selfSub}</div>
      </div>
      <div style={{ opacity: enter, transform: `translateX(${(1 - enter) * 80}px)` }}>
        {SELF_PROTECTION.screenshot ? (
          <Screenshot file={SELF_PROTECTION.screenshot} />
        ) : (
          <OpenCodeSession
            prompt={copy.selfPrompt}
            tool={SELF_PROTECTION.tool}
            command={SELF_PROTECTION.command}
            outcome={{ verdict: "ask", rule: SELF_PROTECTION.rule, reason: SELF_PROTECTION.reason }}
            labels={copy}
            start={0.3}
            chosen={2}
          />
        )}
      </div>
    </AbsoluteFill>
  )
}
