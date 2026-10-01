//! Identity pipeline for ferro-conduit.
//!
//! Every incoming connection is resolved to a [`VerifiedIdentity`] by one of
//! the pluggable validators (API key, OIDC, SPIFFE, mTLS-CN). The identity
//! then flows into restriction-rule evaluation and the audit log.

pub mod api_keys;

/// The canonical representation of a verified principal. Produced once per
/// connection by whichever validator authenticated the client first.
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    /// The canonical subject string.
    /// - API key:   `"api-key:<name>"` (the label given to the key)
    /// - OIDC:      the `sub` claim
    /// - SPIFFE:    the full SPIFFE ID URI
    /// - mTLS:      the certificate Common Name
    pub subject: String,

    /// Human-readable display name when available (OIDC `name` claim, or the
    /// API key label).
    pub display_name: Option<String>,

    /// Group or role memberships. Populated from OIDC claims; empty for API
    /// keys and mTLS unless explicitly mapped.
    pub groups: Vec<String>,

    /// Raw SPIFFE ID URI when the client authenticated via a SPIFFE SVID.
    pub spiffe_id: Option<String>,

    /// Which mechanism was used to authenticate this identity.
    pub auth_method: AuthMethod,

    /// When the credential expires, if known. `None` means indefinite (API
    /// key, mTLS with long-lived cert). Expired credentials are rejected by
    /// the server even if cached.
    pub expires_at: Option<std::time::SystemTime>,
}

/// The mechanism by which a [`VerifiedIdentity`] was established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// Static API key (`Authorization: ApiKey <value>`).
    ApiKey,
    /// OIDC bearer token (`Authorization: Bearer <jwt>` from an external IdP).
    OidcBearer,
    /// SPIFFE X.509 SVID presented during the mTLS handshake.
    SpiffeSvid,
    /// Conventional mTLS certificate; identity derived from the leaf CN.
    MtlsCertificate,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey => f.write_str("ApiKey"),
            Self::OidcBearer => f.write_str("OidcBearer"),
            Self::SpiffeSvid => f.write_str("SpiffeSvid"),
            Self::MtlsCertificate => f.write_str("MtlsCertificate"),
        }
    }
}
