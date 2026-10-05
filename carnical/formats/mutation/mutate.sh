#!/bin/bash
# Mutation testing for package formats.
#
# For every place in the source where a refusal is reported or decided, make a copy of the package in which that one place is
# broken, run the tests, and require them to fail. A mutant that survives is a refusal that no test depends on (or a change that
# does not change behaviour: read each survivor). The three operators are in mutate.awk.
#
# The copy is made outside the repository, so the real files are never touched. Run on Linux or WSL:
#
#   formats/mutation/mutate.sh [workers] [file-filter]
#
# Results: $OUT/mutate.log, one line per mutant (KILLED, SURVIVED, or BROKEN when the mutant did not compile), then a summary.
# Needs bash, awk, go, and the module cache with github.com/goccy/go-yaml (offline is fine).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/../.." && pwd)"
OUT="${OUT:-/tmp/formats-mutation}"
WORKERS="${1:-4}"
FILTER="${2:-}"
export GOWORK=off GOFLAGS=-mod=mod

rm -rf "$OUT"
mkdir -p "$OUT"
BASE="$OUT/base"
mkdir -p "$BASE/formats" "$BASE/inspect" "$BASE/docs"
cp "$SRC/inspect/inspect.go" "$BASE/inspect/"
cp "$SRC/go.sum" "$BASE/"
cp "$SRC/docs/formats.md" "$BASE/docs/"
cat > "$BASE/go.mod" <<'GOMOD'
module github.com/YurilLAB/coraza/carnical

go 1.25.0

require github.com/goccy/go-yaml v1.19.2
GOMOD
for f in "$SRC"/formats/*.go; do
  case "$f" in *e2e_test.go) ;; *) cp "$f" "$BASE/formats/" ;; esac
done
# What the mutants call instead of reporting. The parsers' own reporters stop the parse in every case, so these do too.
cat > "$BASE/formats/zz_mutant.go" <<'GO'
package formats

func (f *finder) noHit(r *rule, off int, d detail) bool                { return false }
func (f *finder) noHitLimit(r *rule, d detail, limit, off int) bool    { return false }
func (p *jsonParser) noSyntax(d detail) bool                           { return false }
func (p *jsonParser) noLimit(d detail, n, at int) bool                 { return false }
func (p *xmlScanner) noSyntax(d detail) bool                           { return false }
func (p *xmlScanner) noLimit(d detail, n int) bool                     { return false }
func (p *gqlParser) noSyntax(d detail) bool                            { return false }
func (p *gqlParser) noLimit(r *rule, d detail, n int) bool             { return false }
GO

# The tests that measure time are not run on mutants: a mutant that loops would only make them slow, and they check no refusal.
SKIP='TestAdversarial|TestYAMLAtItsDefaultCapIsBounded|TestDecompressionIsBounded|TestOneInspectorServes'
cd "$BASE" || exit 1
if ! go test ./formats -vet=off -count=1 -skip "$SKIP" > "$OUT/baseline.log" 2>&1; then
  echo "the unmutated package fails its tests:"; tail -20 "$OUT/baseline.log"; exit 1
fi

# The list of mutants: file, operator, site.
: > "$OUT/list.txt"
for f in "$BASE"/formats/*.go; do
  b=$(basename "$f")
  case "$b" in *_test.go|zz_mutant.go|rules.go|details.go|policy.go|types.go|finder.go) continue ;; esac
  if [ -n "$FILTER" ] && [[ "$b" != *$FILTER* ]]; then continue; fi
  for op in A B C; do
    n=$(awk -v mode=count -v op=$op -f "$HERE/mutate.awk" "$f")
    for ((k=1; k<=n; k++)); do echo "$b $op $k" >> "$OUT/list.txt"; done
  done
done
# ONLY=file runs just the mutants named in it, one "file op site" per line (the survivors of an earlier run, say).
if [ -n "${ONLY:-}" ]; then grep -Fxf "$ONLY" "$OUT/list.txt" > "$OUT/list.only" && mv "$OUT/list.only" "$OUT/list.txt"; fi
total=$(wc -l < "$OUT/list.txt")
echo "$total mutants, $WORKERS workers"

worker() {
  w=$1
  dir="$OUT/w$w"
  cp -r "$BASE" "$dir"
  cd "$dir" || exit 1
  i=0
  while read -r b op k; do
    i=$((i+1))
    [ $(( (i-1) % WORKERS )) -eq "$w" ] || continue
    f="formats/$b"
    cp "$f" "$f.orig"
    awk -v target="$k" -v op="$op" -f "$HERE/mutate.awk" "$f.orig" > "$f"
    line=$(diff "$f.orig" "$f" | grep -m1 '^[0-9]' | sed 's/[acd].*//')
    if go test ./formats -vet=off -count=1 -skip "$SKIP" < /dev/null > "$OUT/run$w.log" 2>&1; then
      echo "SURVIVED $b:$line op $op #$k :: $(sed -n "${line}p" "$f.orig" | sed 's/^[ 	]*//')" >> "$OUT/res$w.log"
    elif grep -q 'build failed\|setup failed' "$OUT/run$w.log"; then
      echo "BROKEN   $b:$line op $op #$k" >> "$OUT/res$w.log"
    else
      echo "KILLED   $b:$line op $op #$k" >> "$OUT/res$w.log"
    fi
    mv "$f.orig" "$f"
  done < "$OUT/list.txt"
}
for ((w=0; w<WORKERS; w++)); do worker $w & done
wait
cat "$OUT"/res*.log | sort > "$OUT/mutate.log"
k=$(grep -c '^KILLED' "$OUT/mutate.log"); s=$(grep -c '^SURVIVED' "$OUT/mutate.log"); b=$(grep -c '^BROKEN' "$OUT/mutate.log")
echo "mutants $total: killed $k, survived $s, did not compile $b" | tee -a "$OUT/mutate.log"
