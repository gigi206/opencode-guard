#!/bin/sh
# Installs the `guard` command for a plugin that OpenCode installed from a Git specifier (README, "From Git").
# Self-contained, so it also works from a raw download. Target directory: GUARD_BIN_DIR, by default ~/.local/bin.
set -eu
bin_dir=${GUARD_BIN_DIR:-$HOME/.local/bin}
target=$bin_dir/guard
# A directory, or a link to one: `mv` would put the launcher inside it.
if [ -d "$target" ]; then
  echo "guard: $target is a directory: nothing installed" >&2
  exit 1
fi
mkdir -p "$bin_dir"
tmp=$(mktemp "$bin_dir/.guard.XXXXXX")
trap 'rm -f "$tmp"' EXIT
cat > "$tmp" <<'WRAPPER'
#!/bin/sh
# `guard` command for a plugin installed by OpenCode from a Git specifier. Node refuses TypeScript under node_modules,
# so the command runs with the Bun inside OpenCode, from the generation OpenCode loads for the configured specifier.
set -eu
config_dir=${OPENCODE_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/opencode}
spec=
for file in "$config_dir/opencode.json" "$config_dir/opencode.jsonc"; do
  [ -f "$file" ] || continue
  spec=$(sed -n 's/.*"package"[[:space:]]*:[[:space:]]*"\([^"/][^"]*opencode-guard[^"]*\)".*/\1/p' "$file" | head -n 1)
  [ -n "$spec" ] && break
done
if [ -z "$spec" ]; then
  echo "guard: no Git specifier of opencode-guard in $config_dir/opencode.json" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  hash=$(printf %s "$spec" | sha256sum | cut -c1-12)
else
  hash=$(printf %s "$spec" | shasum -a 256 | cut -c1-12)
fi
entry=${XDG_CACHE_HOME:-$HOME/.cache}/opencode/npm/git-opencode-guard-$hash
generation=$(ls "$entry" 2>/dev/null | grep -E '^[0-9]+$' | sort -n | tail -n 1 || true)
if [ -z "$generation" ] || [ ! -f "$entry/$generation/node_modules/opencode-guard/bin/guard" ]; then
  echo "guard: $spec is not installed in $entry (start OpenCode once)" >&2
  exit 1
fi
BUN_BE_BUN=1 exec opencode "$entry/$generation/node_modules/opencode-guard/bin/guard" "$@"
WRAPPER
chmod 755 "$tmp"
# Renamed over the target: an existing link is replaced, never written through.
mv -f "$tmp" "$target"
trap - EXIT
echo "guard installed: $target"
case ":$PATH:" in
  *":$bin_dir:"*) ;;
  *) echo "warning: $bin_dir is not in your PATH" >&2 ;;
esac
