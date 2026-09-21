// Shared helper for the per-directory zero-blast-radius boundary sweeps
// (intelligence-platform/, knowledge-platform/, product-platform/ and
// relationship-framework/ each own one in their __tests__/ directory).
//
// WHY THIS EXISTS
// ---------------
// Those sweeps assert that no file outside a guarded directory couples to it.
// They did so with a raw `text.includes("<dir-name>")` over the WHOLE file,
// which also matched the directory name inside COMMENTS. Boundary
// documentation -- a comment that names a sibling directory to explain the
// architecture it mirrors -- is not production coupling, and each sweep's own
// header comment already says so (that is exactly why several __tests__
// directories carry a hand-maintained exemption).
//
// Reading prose as coupling produced false-positive failures (e.g.
// p39-handlers.js, whose only mention of three guarded directories is a
// comment explaining that it follows their never-wired-into-index.js pattern,
// while its actual imports are p20/p21/p25/p26 engines only).
//
// stripComments() removes comments but preserves string and template
// literals, so a real coupling -- an import specifier, a require() path, a
// dynamic import, any path in a string -- is still caught exactly as before.
// This narrows the sweeps to what they are actually asserting: reachable
// production code, not documentation.
//
// This helper deliberately contains NO guarded directory name, so adding it
// to src/__tests__/ cannot itself trip any sweep.

/**
 * Remove line (`//`) and block comments from JavaScript source, preserving
 * string literals, template literals and regular-expression literals so that
 * any path they contain still participates in a boundary scan.
 *
 * Comment bodies are replaced with a single space rather than deleted, so
 * tokens either side of a removed comment cannot be accidentally joined.
 *
 * @param {string} source JavaScript source text.
 * @returns {string} The source with comment bodies removed.
 */
export function stripComments(source) {
  let out = "";
  let i = 0;
  const n = source.length;

  // Tracks whether a `/` begins a regex literal or is a division operator, by
  // remembering the last significant (non-whitespace) emitted character.
  let lastSignificant = "";

  while (i < n) {
    const ch = source[i];
    const next = source[i + 1];

    // ---- line comment ----------------------------------------------------
    if (ch === "/" && next === "/") {
      while (i < n && source[i] !== "\n") i += 1;
      out += " ";
      continue;
    }

    // ---- block comment ---------------------------------------------------
    if (ch === "/" && next === "*") {
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) {
        // Preserve newlines so reported line numbers stay meaningful.
        if (source[i] === "\n") out += "\n";
        i += 1;
      }
      i += 2;
      out += " ";
      continue;
    }

    // ---- string / template literal ---------------------------------------
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      out += ch;
      i += 1;
      while (i < n) {
        if (source[i] === "\\") {
          out += source[i] + (source[i + 1] ?? "");
          i += 2;
          continue;
        }
        out += source[i];
        if (source[i] === quote) {
          i += 1;
          break;
        }
        i += 1;
      }
      lastSignificant = quote;
      continue;
    }

    // ---- regex literal ---------------------------------------------------
    // A `/` is a regex start only where a value cannot already have ended;
    // otherwise it is division. This keeps `a / b` from swallowing source.
    if (ch === "/" && isRegexPosition(lastSignificant)) {
      out += ch;
      i += 1;
      let inClass = false;
      while (i < n) {
        const c = source[i];
        if (c === "\\") {
          out += c + (source[i + 1] ?? "");
          i += 2;
          continue;
        }
        if (c === "[") inClass = true;
        else if (c === "]") inClass = false;
        else if (c === "/" && !inClass) {
          out += c;
          i += 1;
          break;
        } else if (c === "\n") {
          // Unterminated regex -- treat as division after all.
          break;
        }
        out += c;
        i += 1;
      }
      lastSignificant = "/";
      continue;
    }

    out += ch;
    if (!/\s/.test(ch)) lastSignificant = ch;
    i += 1;
  }

  return out;
}

/**
 * True when a `/` at this position starts a regular-expression literal rather
 * than acting as a division operator, judged by the preceding significant
 * character.
 *
 * @param {string} prev Last significant character emitted before the slash.
 */
function isRegexPosition(prev) {
  if (prev === "") return true;
  return "(,=:[!&|?{};+-*%~^<>".includes(prev);
}
