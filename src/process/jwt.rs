use jsonwebtoken::Algorithm;
use serde::{Deserialize, Serialize};
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Claims {
    aud: String, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    nbf: usize, // Optional. Not Before (as UTC timestamp)
    sub: String, // Optional. Subject (whom token refers to)
}

impl Claims {
    pub fn set_aud(&mut self, aud: Option<String>) -> &mut Self {
        if let Some(aud) = aud {
            self.aud = aud;
        }
        self
    }
    pub fn set_exp(&mut self, exp: usize) -> &mut Self {
        self.exp = self.iat + exp;
        self
    }
    pub fn set_iat(&mut self, iat: Option<usize>) -> &mut Self {
        let iat = iat.unwrap_or_else(|| jsonwebtoken::get_current_timestamp() as usize);
        self.iat = iat;
        self
    }
    pub fn set_iss(&mut self, iss: Option<String>) -> &mut Self {
        if let Some(iss) = iss {
            self.iss = iss;
        };
        self
    }
    pub fn set_nbf(&mut self, nbf: Option<usize>) -> &mut Self {
        if let Some(nbf) = nbf {
            self.nbf = nbf;
        }
        self
    }
    pub fn set_sub(&mut self, sub: Option<String>) -> &mut Self {
        if let Some(sub) = sub {
            self.sub = sub;
        }
        self
    }
}
pub fn process_jwt_sign(
    algorithm: Algorithm,
    claims: Claims,
    key: String,
) -> anyhow::Result<String> {
    if algorithm != Algorithm::HS256 {
        return Err(anyhow::anyhow!("Rcli: only support HS256 algorithm now!"));
    }
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(algorithm),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(key.as_bytes()),
    )?;
    Ok(token)
}

pub fn process_jwt_verify(
    token: String,
    key: String,
    algorithm: Algorithm,
) -> anyhow::Result<bool> {
    if algorithm != Algorithm::HS256 {
        return Err(anyhow::anyhow!("Rcli: only support HS256 algorithm now!"));
    }
    let mut validation = jsonwebtoken::Validation::new(Algorithm::HS256);
    validation.validate_aud = false;
    validation.validate_nbf = false;
    let decoded = jsonwebtoken::decode::<Claims>(
        &token,
        &jsonwebtoken::DecodingKey::from_secret(key.as_bytes()),
        &validation,
    )?;
    let res = decoded.claims.exp > jsonwebtoken::get_current_timestamp() as usize;
    println!("{}", serde_json::to_string_pretty(&decoded.claims)?);
    Ok(res)
}
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_jwt_sign() -> anyhow::Result<()> {
        let key = "secret".to_string();
        let mut claims = Claims::default();
        claims
            .set_iat(None)
            .set_exp(3600)
            .set_iss(None)
            .set_nbf(None)
            .set_sub(Some("acme".to_string()))
            .set_aud(Some("device1".to_string()));
        let token = process_jwt_sign(Algorithm::HS256, claims, key)?;
        println!("token: {}", token);
        Ok(())
    }

    #[test]
    fn test_jwt_verify() -> anyhow::Result<()> {
        let key = "secret".to_string();
        let mut claims = Claims::default();
        claims
            .set_iat(None)
            .set_exp(3600)
            .set_iss(None)
            .set_nbf(None)
            .set_sub(None)
            .set_aud(Some("device1".to_string()));
        let token = process_jwt_sign(Algorithm::HS256, claims, key.clone())?;
        let key_error_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJkZXZpY2UxIiwiZXhwIjoxNzE1NTAyODc4LCJpYXQiOjE3MTQyOTMyNzgsImlzcyI6IiIsIm5iZiI6MCwic3ViIjoiYWNtZSJ9.uiKLPaVzAs44wjk5-k-NH-LFuEmZ6AzK8-XECTktJ40".to_string();
        let time_error_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJkZXZpY2UxIiwiZXhwIjoxMjA5NjAwLCJpYXQiOjE3MTQyOTI4NzksImlzcyI6IiIsIm5iZiI6MCwic3ViIjoiYWNtZSJ9.6YHYtcPZFeXayaTpXKx017wS64ydM5lZwVAQHSh_0wA".to_string();
        assert!(process_jwt_verify(token, key.clone(), Algorithm::HS256)?,);
        assert!(process_jwt_verify(key_error_token, key.clone(), Algorithm::HS256).is_err());
        assert!(process_jwt_verify(time_error_token, key.clone(), Algorithm::HS256).is_err());
        Ok(())
    }
}
