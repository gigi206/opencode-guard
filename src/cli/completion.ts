// `guard completion bash|zsh`: a completion script for the shell, to load from its startup file
// (`eval "$(guard completion zsh)"`). The rule identifiers, the redaction formats and the settings are written into it
// when it is generated, from the plugin's own lists: loaded at each shell start, it follows the plugin's version. zsh
// runs the bash function through `bashcompinit`. Nothing is run on a completion.
import { RULE_FEATURES, TARGETED_RULES } from "../rules/features.ts"
import { FORMAT_SUMMARIES } from "../secrets/patterns.ts"
import { SETTINGS, SWITCHES } from "./write.ts"

export const COMMANDS = ["rules", "redaction", "show", "last", "status", "test", "set", "unset", "trust", "untrust", "help", "completion"] as const
export const SHELLS = ["bash", "zsh"] as const

/** Words of a shell list: only the characters of identifiers, so that nothing in them is read by the shell. */
const words = (list: Iterable<string>) => [...list].filter((word) => /^[\w.-]+$/.test(word)).join(" ")

function bashFunction(): string {
  const values = Object.entries(SWITCHES)
    .map(([key, allowed]) => `      ${key}) words="${words(allowed[0] === "true" ? [...allowed, "on", "off"] : allowed)}" ;;`)
    .join("\n")
  return `_guard() {
  local cur=\${COMP_WORDS[COMP_CWORD]} prev=\${COMP_WORDS[COMP_CWORD-1]} cmd=\${COMP_WORDS[1]} sub=\${COMP_WORDS[2]} words=""
  local rules="${words(RULE_FEATURES.keys())}"
  local formats="${words(FORMAT_SUMMARIES.keys())}"
  local settings="${words(Object.keys(SWITCHES))}"
  COMPREPLY=()
  case $prev in
    --agent|--tool|--pattern|--reason|--tools|--flags) return ;;
    --verdict) COMPREPLY=($(compgen -W "ask deny" -- "$cur")); return ;;
    --project) COMPREPLY=($(compgen -d -- "$cur")); return ;;
    --path) COMPREPLY=($(compgen -f -- "$cur")); return ;;
    --explain) [[ $cmd == rules ]] && words=$rules || words=$formats
      COMPREPLY=($(compgen -W "$words" -- "$cur")); return ;;
  esac
  if [[ $COMP_CWORD -eq 1 ]]; then
    words="${words(COMMANDS)}"
  else
    case $cmd in
      rules)
        if [[ $COMP_CWORD -eq 2 ]]; then words="${words([...SETTINGS, "reset", "add", "remove"])} --builtins --custom --explain"
        elif [[ " ${words([...SETTINGS, "reset"])} " == *" $sub "* ]]; then words="$rules --agent --project"
          # A file's exception: off or reset of a rule that accepts them.
          [[ ($sub == off || $sub == reset) && " ${words(TARGETED_RULES)} " == *" \${COMP_WORDS[3]} "* ]] && words="$words --path"
        elif [[ $sub == add ]] && [[ $COMP_CWORD -ge 4 ]]; then words="--pattern --verdict --reason --tools --flags"; fi ;;
      redaction)
        if [[ $COMP_CWORD -eq 2 ]]; then words="off on --builtins --custom --explain"
        elif [[ $sub == off || $sub == on ]] && [[ $COMP_CWORD -eq 3 ]]; then words=$formats; fi ;;
      set)
        if [[ $COMP_CWORD -eq 2 ]]; then words=$settings
        elif [[ $COMP_CWORD -eq 3 ]]; then
          case $sub in
${values}
          esac
        else words="--agent --project"; fi ;;
      unset)
        if [[ $COMP_CWORD -eq 2 ]]; then words=$settings; else words="--agent --project"; fi ;;
      show) words="--agent" ;;
      status) words="--offline" ;;
      test) [[ " \${COMP_WORDS[*]:2:COMP_CWORD-2} " == *" -- "* ]] || words="--agent --model --tool --" ;;
      trust|untrust) words="--all"; COMPREPLY=($(compgen -d -- "$cur")) ;;
      completion) words="${words(SHELLS)}" ;;
    esac
  fi
  COMPREPLY+=($(compgen -W "$words" -- "$cur"))
}
complete -F _guard guard`
}

export function completionScript(shell: (typeof SHELLS)[number]): string {
  const header = `# guard command completion (${shell}); load it from your shell's startup file: eval "$(guard completion ${shell})"`
  if (shell === "bash") return `${header}\n${bashFunction()}\n`
  return `${header}\nautoload -U +X compinit && { (( $+functions[compdef] )) || compinit; }\nautoload -U +X bashcompinit && bashcompinit\n${bashFunction()}\n`
}
