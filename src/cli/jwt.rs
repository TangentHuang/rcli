use crate::cli::verify_file;
use crate::{get_reader, process_jwt_sign, process_jwt_verify, Claims, CmdExecutor};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use jsonwebtoken::Algorithm;
use regex::Regex;
use std::fs;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum JwtSubCommand {
    #[command(about = "Sign JWT")]
    Sign(JwtSignOpts),

    #[command(about = "Verify JWT")]
    Verify(JwtVerifyOpts),
}

#[derive(Debug, Parser)]
pub struct JwtSignOpts {
    #[arg(long, default_value = "HS256" , value_parser=parse_jwt_algorithm)]
    algorithm: Algorithm,

    #[arg(long)]
    aud: Option<String>, // Optional. Audience

    #[arg(long, default_value_t = 6000,value_parser=parse_expire_time)]
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)

    #[arg(long)]
    iat: Option<usize>, // Optional. Issued at (as UTC timestamp)

    #[arg(long)]
    iss: Option<String>, // Optional. Issuer

    #[arg(long)]
    nbf: Option<usize>, // Optional. Not Before (as UTC timestamp)

    #[arg(long)]
    sub: Option<String>, // Optional. Subject (whom token refers to)

    #[arg(long)]
    key: String,

    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Debug, Parser)]
pub struct JwtVerifyOpts {
    #[arg(long, default_value = "HS256" , value_parser=parse_jwt_algorithm)]
    algorithm: Algorithm,

    #[arg(short,long,default_value = "-",value_parser=verify_file)]
    input: String,

    #[arg(long)]
    key: String,
}

fn parse_jwt_algorithm(algorithm: &str) -> anyhow::Result<Algorithm> {
    algorithm
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid algorithm"))
}

fn parse_expire_time(exp: &str) -> anyhow::Result<usize> {
    //example: trans "1d23h20m10s" to seconds (usize)
    //format check
    let format_re = Regex::new(r"^(\d+d)?((2[0-3]|[0-1]?\d)h)?([0-5]?\dm)?([0-5]?\ds)?$")?;
    if !format_re.is_match(exp) {
        //The compiler will report to the unclear warning, but after the test is available, it can be reached
        anyhow::bail!("invalid expire time format, please input like \"1d23h20m10s\"");
    }

    let re = Regex::new(r"(\d+)([dhms])")?;
    let mut seconds_total: usize = 0;

    for cap in re.captures_iter(exp) {
        let value: usize = cap[1].parse()?;
        match &cap[2] {
            "d" => seconds_total += value * 24 * 60 * 60,
            "h" => seconds_total += value * 60 * 60,
            "m" => seconds_total += value * 60,
            "s" => seconds_total += value,
            _ => anyhow::bail!("invalid expire time format"),
        }
    }
    Ok(seconds_total)
}

impl CmdExecutor for JwtSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut claims = Claims::default();
        claims
            .set_aud(self.aud)
            .set_iss(self.iss)
            .set_iat(self.iat)
            .set_exp(self.exp)
            .set_nbf(self.nbf)
            .set_sub(self.sub);
        let token = process_jwt_sign(self.algorithm, claims, self.key)?;
        if let Some(output) = self.output {
            fs::write(output, token)?;
        } else {
            println!("{}", token);
        };
        Ok(())
    }
}

impl CmdExecutor for JwtVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let token = String::from_utf8(buf)?;
        let is_verify = process_jwt_verify(token, self.key, self.algorithm)?;
        if is_verify {
            println!("verify success");
        } else {
            println!("verify failed");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_expire_time() {
        assert!(parse_expire_time("1d23h20m10s").is_ok());
        assert!(parse_expire_time("1d28h20m10s").is_err());
        assert!(parse_expire_time("1d22h99m10s").is_err());
        assert!(parse_expire_time("1d22h30m100s").is_err());
        assert_eq!(
            parse_expire_time("1d23h20m10s").unwrap(),
            24 * 60 * 60 + 23 * 60 * 60 + 20 * 60 + 10
        );
    }
}
