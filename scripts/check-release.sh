#!/usr/bin/env bash
# Checks that the version is ready to release: CHANGELOG.md has a "## [<version>]" entry; given --tag v<version>, that
# the tag names the version in Directory.Build.props; given --unpublished, that at least one package (src/*/*.csproj) isn't
# on nuget.org at that version yet. A version every package already has must be bumped; one some packages have is a
# partial publish (nuget.org refused a new ID), which a rerun finishes, since the push skips what's there. Exits 1 with the
# reason otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."

prefix=$(sed -n 's:.*<VersionPrefix>\(.*\)</VersionPrefix>.*:\1:p' Directory.Build.props)
suffix=$(sed -n 's:.*<VersionSuffix>\(.*\)</VersionSuffix>.*:\1:p' Directory.Build.props)
version="$prefix${suffix:+-$suffix}"
problems=()

tag=""
check_registry=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) tag="${2:-}"; shift 2 ;;
    --unpublished) check_registry=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -n "$tag" && "$tag" != "v$version" ]]; then
  problems+=("the tag is \"$tag\" but Directory.Build.props says $version: tag v$version")
fi

module_version=$(sed -n 's:.*public const string Version = "\(.*\)";.*:\1:p' src/AbpGuard/AbpGuardModule.cs)
if [[ "$module_version" != "$version" ]]; then
  problems+=("AbpGuardModule.Version is \"$module_version\" but Directory.Build.props says $version")
fi

if ! grep -qF "## [$version]" CHANGELOG.md; then
  problems+=("CHANGELOG.md has no \"## [$version]\" entry")
fi

if [[ $check_registry == 1 ]]; then
  lower=$(printf '%s' "$version" | tr '[:upper:]' '[:lower:]')
  published=()
  missing=()
  for project in src/*/*.csproj; do
    # A project not packed yet (IsPackable false until the release that carries it) has nothing to publish.
    grep -q '<IsPackable>false</IsPackable>' "$project" && continue
    id=$(basename "$project" .csproj)
    versions=$(mktemp)
    status=$(curl -s -o "$versions" -w '%{http_code}' "https://api.nuget.org/v3-flatcontainer/$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')/index.json" || true)
    if [[ "$status" == "200" ]] && grep -qF "\"$lower\"" "$versions"; then
      published+=("$id")
    elif [[ "$status" == "200" || "$status" == "404" ]]; then
      missing+=("$id")
    else
      problems+=("can't ask nuget.org for $id's versions (HTTP $status)")
    fi
    rm -f "$versions"
  done
  if [[ ${#missing[@]} -eq 0 && ${#problems[@]} -eq 0 ]]; then
    problems+=("every package is already on nuget.org at $version: bump the version")
  elif [[ ${#published[@]} -gt 0 ]]; then
    echo "AbpGuard $version: finishing a partial publish: ${published[*]} already on nuget.org; ${missing[*]} to push"
  fi
fi

if [[ ${#problems[@]} -gt 0 ]]; then
  for p in "${problems[@]}"; do echo "AbpGuard $version: $p" >&2; done
  exit 1
fi
echo "AbpGuard $version: ready to release"
