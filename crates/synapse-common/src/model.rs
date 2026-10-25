//! Small shared enums whose string forms are also stored in SQLite `CHECK`
//! constraints. A test in `store` inserts every variant to keep the two in sync.

use serde::{Deserialize, Serialize};

macro_rules! str_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub enum $name {
            $( #[serde(rename = $s)] $variant ),+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// Stable lowercase string form (JSON and SQLite).
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $s),+ }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl std::str::FromStr for $name {
            type Err = String;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($s => Ok($name::$variant),)+
                    other => Err(format!("unknown {} {:?}", stringify!($name), other)),
                }
            }
        }
    };
}

str_enum! {
    /// Alert severity, ordered from least to most severe.
    Severity { Low => "low", Medium => "medium", High => "high", Critical => "critical" }
}

str_enum! {
    /// Engine verdict for a process or file.
    Verdict { Benign => "benign", Suspicious => "suspicious", Malicious => "malicious" }
}

str_enum! {
    /// Lifecycle of a response action record.
    ActionStatus {
        DryRun => "dry_run",
        Executed => "executed",
        Failed => "failed",
        Undone => "undone",
        Skipped => "skipped",
        Pending => "pending",
        Rejected => "rejected",
    }
}

str_enum! {
    /// Lifecycle of an AI-generated rule proposal.
    ProposalStatus {
        Pending => "pending",
        Approved => "approved",
        Rejected => "rejected",
        AutoRejected => "auto_rejected",
    }
}

str_enum! {
    /// Classification of a hash-database entry.
    HashClass { Bad => "bad", Good => "good" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_str_and_serde() {
        for &s in Severity::ALL {
            assert_eq!(s.as_str().parse::<Severity>(), Ok(s));
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
            assert_eq!(serde_json::from_str::<Severity>(&json).unwrap(), s);
        }
        assert!("nope".parse::<Verdict>().is_err());
    }

    #[test]
    fn severity_is_ordered() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::High < Severity::Critical);
    }
}
