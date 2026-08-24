//! The shared vocabulary for findings: what a check reports, and how a caller counts it.
//!
//! Lives here rather than beside the manifest checks so that a signing or registry tool,
//! which runs only the canonical-form rules, still speaks the same type as the wallet.

/// Severity of a single validation finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A definite problem: the file will not run correctly as written.
    Error,
    /// A likely mistake or smell, but not necessarily fatal.
    Warning,
}

/// One finding produced by [`validate`].
#[derive(Debug, Clone)]
pub struct Issue {
    pub severity: Severity,
    /// Dot-path to the offending element, e.g. `actions.Pay.outputs.p2pk_out`.
    pub location: String,
    pub message: String,
}

/// The result of validating a manifest file.
#[derive(Debug, Default)]
pub struct Report {
    pub issues: Vec<Issue>,
}

impl Report {
    /// Record a definite problem.
    pub fn error(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Error,
            location: location.into(),
            message: message.into(),
        });
    }

    /// Record a likely mistake that is not necessarily fatal.
    pub fn warn(&mut self, location: impl Into<String>, message: impl Into<String>) {
        self.issues.push(Issue {
            severity: Severity::Warning,
            location: location.into(),
            message: message.into(),
        });
    }

    /// Fold another report's findings into this one, preserving order.
    ///
    /// The checks are split by what they need — a parsed [`Manifest`], the raw text, the
    /// filesystem — but a user is looking at one file and wants one list.
    pub fn extend(&mut self, other: Report) {
        self.issues.extend(other.issues);
    }

    /// Number of error-severity issues.
    pub fn errors(&self) -> usize {
        self.issues.iter().filter(|i| i.severity == Severity::Error).count()
    }

    /// Number of warning-severity issues.
    pub fn warnings(&self) -> usize {
        self.issues.iter().filter(|i| i.severity == Severity::Warning).count()
    }

    /// True when there are no errors (warnings are allowed).
    pub fn is_ok(&self) -> bool {
        self.errors() == 0
    }
}
