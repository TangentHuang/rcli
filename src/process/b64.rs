use crate::Base64Format;
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD};
use base64::Engine as _;
use std::io::Read;
pub fn process_b64_encode(input: &str, format: Base64Format) -> anyhow::Result<()> {
    let mut reader = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    let encode = match format {
        Base64Format::Standard => BASE64_STANDARD.encode(buf),
        Base64Format::UrlSafe => BASE64_URL_SAFE_NO_PAD.encode(buf),
    };
    println!("{}", encode);
    Ok(())
}
pub fn process_b64_decode(input: &str, format: Base64Format) -> anyhow::Result<()> {
    let mut reader = get_reader(input)?;
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;
    buf = buf.trim().to_string();
    let decode = match format {
        Base64Format::Standard => BASE64_STANDARD.decode(buf)?,
        Base64Format::UrlSafe => BASE64_URL_SAFE_NO_PAD.decode(buf)?,
    };
    let decode = String::from_utf8(decode)?;
    println!("{}", decode);
    Ok(())
}

fn get_reader(input: &str) -> anyhow::Result<Box<dyn Read>> {
    let reader: Box<dyn Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(input)?)
    };
    Ok(reader)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b64_encode() {
        let input = "Cargo.toml";
        let format = Base64Format::Standard;
        assert!(process_b64_encode(input, format).is_ok());
    }

    #[test]
    fn test_b64_decode() {
        let input = "tests/b64_test/b64_decode_test.b64";
        let format = Base64Format::UrlSafe;
        assert!(process_b64_decode(input, format).is_ok());
    }
}
