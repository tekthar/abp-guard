#!/usr/bin/env bash
# Checks that the name of the product Guard came from appears nowhere: in the repository's files, or with --packages
# <dir>, in the packages' files and their assemblies' strings. AbpGuard is its own product; a host that shipped under
# the old names sets them itself (docs/upgrading.md, the one file here that lists them). Exits 1 with each place found.
#
# The repository's own address is the one exception while the repository still lives at it: NuGet and SourceLink write
# it into every package. It's reported as a warning until the repository moves and Directory.Build.props follows.
set -euo pipefail
cd "$(dirname "$0")/.."

pattern='[Tt][Oo][Dd][Aa](?![Yy])|تودا'
# Files that name the old product on purpose: the history, the guide for hosts moving over, and this check.
allowed=(CHANGELOG.md docs/upgrading.md scripts/check-names.sh)
# Its web address, and SourceLink's address for its raw files.
repository='(github|raw\.githubusercontent)\.com/todahq/toda-guard'

found=0
warned=0
report() { # where, line
  if printf '%s' "$2" | grep -qP "$repository" && ! printf '%s' "$2" | sed -E "s#$repository##g" | grep -qP "$pattern"; then
    if [[ $warned == 0 ]]; then
      echo "::warning::The repository's address (github.com/todahq/toda-guard) still names the old product; move the repository and update Directory.Build.props." >&2
      warned=1
    fi
    return
  fi
  echo "$1: $2" >&2
  found=1
}

if [[ "${1:-}" == "--packages" ]]; then
  dir="${2:?give the folder the packages were packed to}"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
  for package in "$dir"/*.nupkg "$dir"/*.snupkg; do
    [[ -e "$package" ]] || continue
    mkdir -p "$work/$(basename "$package")"
    unzip -q -o "$package" -d "$work/$(basename "$package")"
  done
  while IFS= read -r file; do
    while IFS= read -r line; do report "${file#"$work"/}" "$line"; done < <(grep -aoP "[^\x00-\x1f\"<>]{0,40}($pattern)[^\x00-\x1f\"<>]{0,40}" "$file" | sort -u)
  done < <(grep -rlaP "$pattern" "$work" || true)
else
  exclude=()
  for path in "${allowed[@]}"; do exclude+=(":!$path"); done
  while IFS= read -r hit; do
    report "${hit%%:*}" "${hit#*:}"
  done < <(git grep -nP "$pattern" -- . "${exclude[@]}" || true)
  # File and folder names too.
  while IFS= read -r path; do report "$path" "(its name)"; done < <(git ls-files | grep -P "$pattern" | grep -vxF -f <(printf '%s\n' "${allowed[@]}") || true)
fi

if [[ $found == 1 ]]; then
  echo "The old product's name is above: AbpGuard names no product but its own." >&2
  exit 1
fi
echo "No old product name${1:+ in the packages}."
