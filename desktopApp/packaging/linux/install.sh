#!/usr/bin/env bash
# Installs Cruciform for the desktop for this user (no root): the app image under
# ~/.local/share/cruciform-desktop, a launcher in ~/.local/bin, and a .desktop entry that
# registers the void-which-binds: scheme, so a browser's sign-in link opens the app.
# Run it from the unpacked release tarball. `install.sh --uninstall` removes all three, and
# neither ever touches a directory standing where the launcher or the entry should be.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
data="${XDG_DATA_HOME:-$HOME/.local/share}"
app_dir="$data/cruciform-desktop"
bin="$HOME/.local/bin/cruciform-desktop"
entry="$data/applications/cruciform-desktop.desktop"

# The launcher and the entry are single files (or a symlink). A real directory at either path
# is not ours: refuse rather than install into it or delete it.
refuse_dirs() {
  local p
  for p in "$bin" "$entry"; do
    if [ -d "$p" ] && [ ! -L "$p" ]; then
      echo "$p is a directory, not Cruciform's file; leaving it alone. Move it aside and run this again." >&2
      exit 1
    fi
  done
}

if [ "${1:-}" = "--uninstall" ]; then
  refuse_dirs
  rm -f "$bin" "$entry"
  # Only the app image this script installed is removed recursively.
  rm -rf "$app_dir/app"
  rmdir "$app_dir" 2>/dev/null || true
  command -v update-desktop-database >/dev/null && update-desktop-database "$data/applications" || true
  echo "Removed Cruciform. This computer's device directory was not touched."
  exit 0
fi

test -x "$here/cruciform-desktop/bin/cruciform-desktop" || {
  echo "Run this from the unpacked release (cruciform-desktop/bin/cruciform-desktop not found)." >&2
  exit 1
}

refuse_dirs
mkdir -p "$app_dir" "$(dirname "$bin")" "$(dirname "$entry")"
rm -rf "$app_dir/app"
cp -a "$here/cruciform-desktop" "$app_dir/app"
ln -sfn "$app_dir/app/bin/cruciform-desktop" "$bin"
# The launcher path as one quoted desktop-entry Exec argument (Desktop Entry spec, "The Exec
# key"): inside quotes, ", `, $ and \ take a backslash, and the string-level escape doubles
# every backslash again; % is %%. A newline cannot be represented, so it is refused.
exec_arg() {
  local s=$1
  case $s in *$'\n'*) echo "The install path contains a newline; choose another HOME." >&2; exit 1 ;; esac
  s=${s//\\/\\\\\\\\}
  s=${s//\"/\\\\\"}
  s=${s//\`/\\\\\`}
  s=${s//\$/\\\\\$}
  s=${s//%/%%}
  printf '"%s"' "$s"
}
# Substituted with awk's index/substr, from the environment, so nothing in the path is read
# as a pattern or replacement metacharacter.
BIN_ARG="$(exec_arg "$bin")" awk '{ i = index($0, "@BIN@"); if (i) $0 = substr($0, 1, i - 1) ENVIRON["BIN_ARG"] substr($0, i + 5); print }' \
  "$here/cruciform-desktop.desktop" > "$entry"

command -v update-desktop-database >/dev/null && update-desktop-database "$data/applications" || true
echo "Installed Cruciform: $bin"
if command -v xdg-mime >/dev/null; then
  mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}" # xdg-mime writes mimeapps.list there
  xdg-mime default cruciform-desktop.desktop x-scheme-handler/void-which-binds || true
  # The request can be overridden by policy or need approval: report what is now in effect.
  actual="$(xdg-mime query default x-scheme-handler/void-which-binds 2>/dev/null || true)"
  if [ "$actual" = "cruciform-desktop.desktop" ]; then
    echo "void-which-binds: links now open it."
  else
    echo "void-which-binds: links are still handled by '${actual:-nothing}', not Cruciform: your desktop's settings or policy kept it. Choose Cruciform for these links there." >&2
  fi
else
  echo "xdg-mime was not found, so void-which-binds: links were not registered. Install xdg-utils and run this again." >&2
fi
