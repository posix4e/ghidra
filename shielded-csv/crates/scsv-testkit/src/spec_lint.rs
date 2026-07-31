//! Enforces the `spec/` convention: files are dependency-numbered `NN-NAME.md`,
//! and a file may only reference specs with a strictly lower number (plus the
//! non-numbered `GLOSSARY.md`). This keeps the specification a DAG that can be
//! read top-to-bottom.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// A reference `NN-...` found inside a spec file, with the line it appeared on.
#[derive(Debug)]
struct Reference {
    number: u32,
    line: usize,
}

/// Lint the given `spec/` directory. Returns the list of violations (empty when
/// the directory is clean).
pub fn lint_spec_dir(dir: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let mut numbered: BTreeMap<u32, String> = BTreeMap::new();
    let mut has_glossary = false;

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return vec![format!("cannot read spec dir {}: {e}", dir.display())],
    };

    let mut files: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".md") {
            continue;
        }
        files.push(name);
    }
    files.sort();

    for name in &files {
        if name == "GLOSSARY.md" {
            has_glossary = true;
            continue;
        }
        match parse_number(name) {
            Some(n) => {
                if let Some(prev) = numbered.insert(n, name.clone()) {
                    problems.push(format!("duplicate spec number {n:02}: {prev} and {name}"));
                }
            }
            None => problems.push(format!(
                "spec file `{name}` is not `NN-NAME.md` or `GLOSSARY.md`"
            )),
        }
    }

    if !has_glossary {
        problems.push("missing spec/GLOSSARY.md".to_string());
    }

    // Forward-reference check: within NN-*.md, any `MM-` spec reference must have
    // MM < NN (self-references and GLOSSARY are allowed).
    for (&num, name) in &numbered {
        let path = dir.join(name);
        let body = match fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) => {
                problems.push(format!("cannot read {name}: {e}"));
                continue;
            }
        };
        for r in find_references(&body) {
            if r.number >= num && r.number != num {
                problems.push(format!(
                    "{name}:{} references spec {:02} (>= its own {:02}) — forward reference",
                    r.line, r.number, num
                ));
            }
        }
    }

    problems
}

/// Parse the leading `NN` from `NN-NAME.md`.
fn parse_number(name: &str) -> Option<u32> {
    let (prefix, rest) = name.split_once('-')?;
    if !rest.ends_with(".md") {
        return None;
    }
    if prefix.len() != 2 {
        return None;
    }
    prefix.parse::<u32>().ok()
}

/// Find `NN-` style spec references inside markdown, e.g. `spec/13-SEIZURE.md`
/// or `` `14-AIR-STATEMENT` ``. We look for a two-digit run followed by `-` and
/// an uppercase letter, which is specific enough to avoid matching dates or
/// hex.
fn find_references(body: &str) -> Vec<Reference> {
    let mut refs = Vec::new();
    for (i, line) in body.lines().enumerate() {
        let bytes = line.as_bytes();
        let mut j = 0;
        while j + 3 < bytes.len() {
            if bytes[j].is_ascii_digit()
                && bytes[j + 1].is_ascii_digit()
                && bytes[j + 2] == b'-'
                && bytes[j + 3].is_ascii_uppercase()
            {
                // Reject if the char before the two digits is alphanumeric
                // (avoids matching inside longer tokens like a git hash).
                let boundary_ok = j == 0 || !bytes[j - 1].is_ascii_alphanumeric();
                if boundary_ok {
                    let n = (bytes[j] - b'0') as u32 * 10 + (bytes[j + 1] - b'0') as u32;
                    refs.push(Reference {
                        number: n,
                        line: i + 1,
                    });
                }
                j += 4;
            } else {
                j += 1;
            }
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_number_forms() {
        assert_eq!(parse_number("00-OVERVIEW.md"), Some(0));
        assert_eq!(parse_number("13-SEIZURE.md"), Some(13));
        assert_eq!(parse_number("GLOSSARY.md"), None);
        assert_eq!(parse_number("README.md"), None);
        assert_eq!(parse_number("1-X.md"), None);
    }

    #[test]
    fn detects_forward_reference() {
        let refs = find_references("this cites 14-AIR-STATEMENT and 02-KEYS");
        let nums: Vec<u32> = refs.iter().map(|r| r.number).collect();
        assert_eq!(nums, vec![14, 2]);
    }

    #[test]
    fn ignores_non_spec_digit_runs() {
        // "31-" here is followed by lowercase, so not a spec reference.
        let refs = find_references("bitcoin 31-bit thing and 2026-07-31 date");
        assert!(refs.is_empty(), "got {refs:?}");
    }

    #[test]
    fn workspace_spec_dir_is_clean() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("spec");
        let problems = lint_spec_dir(&dir);
        assert!(
            problems.is_empty(),
            "spec lint failures:\n{}",
            problems.join("\n")
        );
    }
}
