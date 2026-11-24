#!/usr/bin/env bash
# Offline test of scripts/generic-images.sh check FILE. The recorded values
# of a build pass and a differing value fails. FILE is data: check accepts
# only the names and value formats that build writes, each name once, and
# refuses any other line before it compares. FILE can come from another
# party (a release's published fingerprints-<chain>.txt), so no line of it
# may become part of a sed program, run a command or write a file.
#
# The script runs from a copy of itself and the two common.sh files it
# sources, in a temporary folder whose build/ holds fake build outputs. No
# image is built and nothing outside that folder is written. The case with
# sed's e command needs GNU sed and is skipped, with a line saying so,
# without it. The case with the w flag runs with any sed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS  $*"; }
bad() { fail=$((fail + 1)); echo "FAIL  $*"; }

R="$T/repo"
mkdir -p "$R/scripts" "$R/platform-azure/deploy"
cp "$ROOT/scripts/generic-images.sh" "$ROOT/scripts/common.sh" "$R/scripts/"
cp "$ROOT/platform-azure/deploy/common.sh" "$R/platform-azure/deploy/"

# Fake outputs of a mainnet build of the default variant.
B="$R/build"
mkdir -p "$B/nitro" "$B/aarch64/bin" "$B/x86_64/bin" "$B/azure" "$B/gcp"
printf '{"Measurements": {"HashAlgorithm": "Sha384 { ... }", "PCR0": "%s", "PCR1": "%s", "PCR2": "%s"}}\n' \
  "$(printf 'a%.0s' {1..96})" "$(printf 'b%.0s' {1..96})" "$(printf 'c%.0s' {1..96})" >"$B/nitro/build-enclave-aarch64.json"
for f in aarch64/bin/runner-aws aarch64/bin/hostagent aarch64/bin/forwarder aarch64/bin/udprelay x86_64/bin/runner-azure x86_64/bin/runner-gcp; do
  echo "fake $f" >"$B/$f"
done
echo "sha256:$(printf '1%.0s' {1..64})" >"$B/azure/runner.digest"
printf '2%.0s' {1..64} >"$B/azure/policy.sha256"
echo "sha256:$(printf '3%.0s' {1..64})" >"$B/gcp/runner.digest"
sha() { sha256sum <"$1" | cut -d' ' -f1; }
{
  echo "# generic images, as generic-images.sh build writes them"
  echo "nitro.PCR0 $(printf 'a%.0s' {1..96})"
  echo "nitro.PCR1 $(printf 'b%.0s' {1..96})"
  echo "nitro.PCR2 $(printf 'c%.0s' {1..96})"
  echo "nitro.runner $(sha "$B/aarch64/bin/runner-aws")"
  echo "parent.hostagent $(sha "$B/aarch64/bin/hostagent")"
  echo "parent.forwarder $(sha "$B/aarch64/bin/forwarder")"
  echo "parent.udprelay $(sha "$B/aarch64/bin/udprelay")"
  echo "azure.image sha256:$(printf '1%.0s' {1..64})"
  echo "azure.cce_policy $(printf '2%.0s' {1..64})"
  echo "azure.runner $(sha "$B/x86_64/bin/runner-azure")"
  echo "gcp.image sha256:$(printf '3%.0s' {1..64})"
  echo "gcp.runner $(sha "$B/x86_64/bin/runner-gcp")"
} >"$T/fp.txt"

# check FILE: generic-images.sh check FILE on the fake build; output in $T/out.
check() { env -u CHAIN -u CHAIN_JSON -u DVT -u SIGNER_BUILD_OVERLAY_DIR bash "$R/scripts/generic-images.sh" check "$1" >"$T/out" 2>&1; }
show() { sed 's/^/      /' "$T/out"; }

if check "$T/fp.txt" && [ "$(grep -c '^ok ' "$T/out")" = 12 ]; then
  ok "check: the recorded values of the build, ok for each of the 12"
else
  bad "check: the recorded values of the build do not pass"; show
fi
sed "s/^parent.forwarder .*/parent.forwarder $(printf '0%.0s' {1..64})/" "$T/fp.txt" >"$T/fp-diff.txt"
if ! check "$T/fp-diff.txt" && grep -q "^FAIL  parent.forwarder '" "$T/out" && [ "$(grep -c '^ok ' "$T/out")" = 11 ]; then
  ok "check: one differing value fails, with its name"
else
  bad "check: a differing value of parent.forwarder"; show
fi

# A name that is not a sed-safe word must not reach a sed program. With
# sed's w flag the name x//w<dir>/w would write the file "<dir>/w /p", here
# in a folder "w " made for it.
mkdir "$T/w "
{ cat "$T/fp.txt"; echo "x//w$T/w 00"; } >"$T/fp-w.txt"
rc=0
check "$T/fp-w.txt" || rc=$?
if [ ! -e "$T/w /p" ] && [ "$rc" != 0 ]; then
  ok "check: a name with sed's w flag writes no file and fails"
else
  bad "check: a name in FILE is run as sed code: the w flag wrote $T/w /p (exit $rc)"; show
fi
# The same with GNU sed's e command: the name runs a shell command.
if sed --version 2>/dev/null | grep -q GNU; then
  # shellcheck disable=SC2016 # ${IFS} is for the shell that sed's e starts
  { cat "$T/fp.txt"; echo 'x//;etouch${IFS}'"$T"'/e-ran;# 00'; } >"$T/fp-e.txt"
  rc=0
  check "$T/fp-e.txt" || rc=$?
  if [ ! -e "$T/e-ran" ] && [ "$rc" != 0 ]; then
    ok "check: a name with sed's e command runs nothing and fails"
  else
    bad "check: a name in FILE is run as sed code: the e command ran touch (exit $rc)"; show
  fi
else
  echo "skip  check: sed's e command (sed is not GNU sed)"
fi

# Lines that build never writes are refused, and so is a file that leaves a
# name out or gives one twice.
refuse() { # refuse DESCRIPTION FILE
  if ! check "$2" && grep -q 'generic-images: ' "$T/out" && ! grep -q '^ok ' "$T/out"; then
    ok "check: refuses $1 before it compares"
  else
    bad "check: does not refuse $1"; show
  fi
}
{ cat "$T/fp.txt"; echo "nitro.PCR3 $(printf 'a%.0s' {1..96})"; } >"$T/fp-unknown.txt"
refuse "an unknown name" "$T/fp-unknown.txt"
sed 's/^nitro.PCR1 .*/nitro.PCR1 abc/' "$T/fp.txt" >"$T/fp-short.txt"
refuse "a PCR value that is not 96 hex digits" "$T/fp-short.txt"
sed 's/^azure.image sha256:/azure.image /' "$T/fp.txt" >"$T/fp-digest.txt"
refuse "an image digest without sha256:" "$T/fp-digest.txt"
sed 's/^gcp.runner .*/& extra/' "$T/fp.txt" >"$T/fp-extra.txt"
refuse "a line with a third word" "$T/fp-extra.txt"
sed '/^parent.udprelay /d' "$T/fp.txt" >"$T/fp-missing.txt"
refuse "a file without one of the names" "$T/fp-missing.txt"
{ cat "$T/fp.txt"; grep '^gcp.image ' "$T/fp.txt"; } >"$T/fp-twice.txt"
refuse "a name given twice" "$T/fp-twice.txt"
sed 's/^azure.cce_policy .*/azure.cce_policy none/' "$T/fp.txt" >"$T/fp-none.txt"
mv "$B/azure/policy.sha256" "$B/azure/policy.sha256.bak"
if check "$T/fp-none.txt" && [ "$(grep -c '^ok ' "$T/out")" = 12 ]; then
  ok "check: azure.cce_policy none, as build writes it without a policy"
else
  bad "check: azure.cce_policy none"; show
fi
mv "$B/azure/policy.sha256.bak" "$B/azure/policy.sha256"

# A release's fingerprints-<chain>.txt (release/release-build.sh) adds the
# lane lines variant, build_variant, commit and chain after the 12 names;
# releases before build_variant existed have the other three. The build
# outputs record no lane values, so check prints each as not compared.
lane() { printf 'variant prod\nbuild_variant default\ncommit %s\nchain hoodi\n' "$(printf 'ab%.0s' {1..20})"; }
{ cat "$T/fp.txt"; lane; } >"$T/fp-release.txt"
if check "$T/fp-release.txt" && [ "$(grep -c '^ok ' "$T/out")" = 12 ] && [ "$(grep -c 'not compared' "$T/out")" = 4 ]; then
  ok "check: a release file, its four lane lines shown as not compared"
else
  bad "check: a release file with lane lines"; show
fi
{ cat "$T/fp.txt"; lane | grep -v '^build_variant '; } >"$T/fp-release-old.txt"
if check "$T/fp-release-old.txt" && [ "$(grep -c '^ok ' "$T/out")" = 12 ] && [ "$(grep -c 'not compared' "$T/out")" = 3 ]; then
  ok "check: a release file without build_variant"
else
  bad "check: a release file without build_variant"; show
fi
sed 's/^variant prod/variant debug/' "$T/fp-release.txt" >"$T/fp-lane-variant.txt"
refuse "a lane variant other than test or prod" "$T/fp-lane-variant.txt"
sed 's/^build_variant default/build_variant fast/' "$T/fp-release.txt" >"$T/fp-lane-bv.txt"
refuse "a build_variant other than default or dvt" "$T/fp-lane-bv.txt"
sed 's/^commit .*/commit abc123/' "$T/fp-release.txt" >"$T/fp-lane-commit.txt"
refuse "a commit that is not 40 hex digits" "$T/fp-lane-commit.txt"
sed 's/^chain hoodi/chain sepolia/' "$T/fp-release.txt" >"$T/fp-lane-chain.txt"
refuse "a chain this repo does not build" "$T/fp-lane-chain.txt"
{ cat "$T/fp-release.txt"; echo "chain hoodi"; } >"$T/fp-lane-twice.txt"
refuse "a lane line given twice" "$T/fp-lane-twice.txt"

echo "generic-images-test: $pass passed, $fail failed"
[ "$fail" = 0 ]
