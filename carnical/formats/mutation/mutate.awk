# Source mutation for package formats. Three operators, chosen with op=, and the k-th site (counting from 1, in reading order):
#
#   op=A  a call of .hit( or .hitLimit( becomes .noHit( or .noHitLimit(: the finding is not reported and the scan goes on.
#   op=B  a call of .syntax( or .limit( (the parsers' own error reporters) becomes .noSyntax( or .noLimit(: the parser still stops,
#         but nothing is reported, so the refusal is lost.
#   op=C  an "if" whose body reports something (a hit, a limit or a syntax error within the next three lines) gets its condition
#         replaced by false: the check never fires, which is what deleting the check would do.
#
# With mode=count it prints how many sites there are and changes nothing.
function replace_calls(line, pats, reps, np,    out, best, bi, i, p, pos, found) {
  out = ""
  while (1) {
    best = 0; bi = 0
    for (i = 1; i <= np; i++) {
      p = index(line, pats[i])
      if (p != 0 && (best == 0 || p < best)) { best = p; bi = i }
    }
    if (best == 0) { return out line }
    n++
    if (mode != "count" && n == target) {
      out = out substr(line, 1, best - 1) reps[bi]
      mutated = 1
    } else {
      out = out substr(line, 1, best + length(pats[bi]) - 1)
    }
    line = substr(line, best + length(pats[bi]))
  }
}
function reports(s) {
  return index(s, ".hit(") || index(s, ".hitLimit(") || index(s, ".syntax(") || index(s, ".limit(")
}
{ lines[NR] = $0 }
END {
  np = 0
  if (op == "A") { pats[1] = ".hit("; reps[1] = ".noHit("; pats[2] = ".hitLimit("; reps[2] = ".noHitLimit("; np = 2 }
  if (op == "B") { pats[1] = ".syntax("; reps[1] = ".noSyntax("; pats[2] = ".limit("; reps[2] = ".noLimit("; np = 2 }
  for (i = 1; i <= NR; i++) {
    line = lines[i]
    if (op == "C") {
      idx = index(line, "if ")
      pre = substr(line, 1, idx - 1)
      okpre = (idx > 0 && (pre ~ /^[ \t]*$/ || pre ~ /^[ \t]*\} else $/))
      if (okpre && substr(line, length(line) - 1) == " {" && !reports(line) && (reports(lines[i+1]) || reports(lines[i+2]) || reports(lines[i+3]))) {
        n++
        if (mode != "count" && n == target) {
          cond = substr(line, idx + 3, length(line) - (idx + 3) - 1)
          line = substr(line, 1, idx + 2) "false && (" cond ") {"
          mutated = 1
        }
      }
      if (mode != "count") print line
    } else {
      out = replace_calls(line, pats, reps, np)
      if (mode != "count") print out
    }
  }
  if (mode == "count") print n + 0
}
