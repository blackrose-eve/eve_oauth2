use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EveSsoMetaData {
    pub authorization_endpoint: String,
    pub code_challenge_methods_supported: Vec<String>,
    pub issuer: String,
    pub jwks_uri: String,
    pub response_types_supported: Vec<String>,
    pub revocation_endpoint: String,
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint: String,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EveJwtKeys {
    #[serde(rename = "SkipUnresolvedJsonWebKeys")]
    pub skip_unresolved_json_web_keys: bool,
    pub keys: Vec<EveJwtKey>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "alg")]
pub enum EveJwtKey {
    RS256 {
        e: String,
        kid: String,
        kty: String,
        n: String,
        r#use: String,
    },
    ES256 {
        crv: String,
        kid: String,
        kty: String,
        r#use: String,
        x: String,
        y: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EveJwtClaims {
    pub scp: Option<Vec<String>>,
    pub jti: String,
    pub kid: String,
    pub sub: String,
    pub azp: String,
    pub tenant: String,
    pub tier: String,
    pub region: String,
    pub aud: String,
    pub name: String,
    pub owner: String,
    pub exp: u64,
    pub iat: u64,
    pub iss: String,
}
