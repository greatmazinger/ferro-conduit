//! Static API-key validator.
//!
//! Keys are configured at server startup as `name=value` pairs. On every
//! connection the client presents its key via `Authorization: ApiKey <value>`.
//! Lookup is O(1) (HashMap). Keys never expire; remove a key from config and
//! reload to revoke it.

use std::collections::HashMap;

use super::{AuthMethod, VerifiedIdentity};

/// Holds the server-side set of valid API keys.
///
/// Each key has a *name* (a human-readable label used in logs and the
/// identity subject) and a *value* (the secret presented by the client).
///
/// The validator is immutable after construction — reconfiguration requires
/// rebuilding it (which `run_server_impl` does on restart; live reload is a
/// future enhancement).
#[derive(Clone, Default)]
pub struct ApiKeyValidator {
    /// Maps `value → name`. Reversed from the config order so lookup is O(1).
    keys: HashMap<String, String>,
}

impl std::fmt::Debug for ApiKeyValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyValidator")
            .field("names", &self.keys.values().collect::<Vec<_>>())
            .finish()
    }
}

impl ApiKeyValidator {
    /// Build a validator from a list of `(name, value)` pairs.
    ///
    /// Duplicate *values* are silently last-write-wins (same as HashMap
    /// insert semantics). Duplicate *names* are allowed.
    pub fn new(keys: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            keys: keys.into_iter().map(|(name, value)| (value, name)).collect(),
        }
    }

    /// Parse a slice of `"name=value"` strings (as provided via CLI).
    ///
    /// Returns an error if any entry does not contain exactly one `=`, or
    /// if either side is empty (an empty value would let a bare
    /// `Authorization: ApiKey ` header authenticate).
    pub fn from_config(entries: &[String]) -> anyhow::Result<Self> {
        let pairs = entries
            .iter()
            .map(|s| {
                let (name, value) = s.split_once('=').ok_or_else(|| {
                    anyhow::anyhow!("invalid --api-key entry: expected \"name=value\" with a non-empty name and value")
                })?;
                if name.is_empty() || value.is_empty() {
                    return Err(anyhow::anyhow!(
                        "invalid --api-key entry: expected \"name=value\" with a non-empty name and value"
                    ));
                }
                Ok((name.to_string(), value.to_string()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self::new(pairs))
    }

    /// Returns `true` if no API keys are configured (validator is a no-op).
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Validate an API key value. Returns `Some(VerifiedIdentity)` on success,
    /// `None` if the key is not recognised.
    pub fn validate(&self, key_value: &str) -> Option<VerifiedIdentity> {
        let name = self.keys.get(key_value)?;
        Some(VerifiedIdentity {
            subject: format!("api-key:{name}"),
            display_name: Some(name.clone()),
            groups: vec![],
            spiffe_id: None,
            auth_method: AuthMethod::ApiKey,
            expires_at: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator() -> ApiKeyValidator {
        ApiKeyValidator::new([
            ("alice".to_string(), "secret-alice".to_string()),
            ("bob".to_string(), "secret-bob".to_string()),
        ])
    }

    #[test]
    fn valid_key_returns_identity() {
        let v = make_validator();
        let id = v.validate("secret-alice").expect("should match");
        assert_eq!(id.subject, "api-key:alice");
        assert_eq!(id.display_name.as_deref(), Some("alice"));
        assert_eq!(id.auth_method, AuthMethod::ApiKey);
        assert!(id.groups.is_empty());
        assert!(id.expires_at.is_none());
    }

    #[test]
    fn invalid_key_returns_none() {
        let v = make_validator();
        assert!(v.validate("wrong-key").is_none());
    }

    #[test]
    fn from_config_parses_name_value() {
        let entries = vec!["myteam=supersecret".to_string(), "ci=ci-token".to_string()];
        let v = ApiKeyValidator::from_config(&entries).expect("parses ok");
        assert!(v.validate("supersecret").is_some());
        assert!(v.validate("ci-token").is_some());
        assert!(v.validate("myteam").is_none());
    }

    #[test]
    fn from_config_errors_on_missing_equals() {
        let entries = vec!["no-equals-here".to_string()];
        assert!(ApiKeyValidator::from_config(&entries).is_err());
    }

    #[test]
    fn from_config_errors_on_empty_name_or_value() {
        assert!(ApiKeyValidator::from_config(&["ci=".to_string()]).is_err());
        assert!(ApiKeyValidator::from_config(&["=secret".to_string()]).is_err());
    }

    #[test]
    fn is_empty_when_no_keys() {
        let v = ApiKeyValidator::new(Vec::<(String, String)>::new());
        assert!(v.is_empty());
    }

    #[test]
    fn debug_does_not_leak_secrets() {
        let s = format!("{:?}", make_validator());
        assert!(s.contains("alice"), "expected debug to include the key name, got {s}");
        assert!(!s.contains("secret-alice"), "expected debug to hide the key value, got {s}");
        assert!(!s.contains("secret-bob"), "expected debug to hide the key value, got {s}");
    }
}
