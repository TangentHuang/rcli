use crate::cli::verify_file;
use crate::cli::verify_path;
use crate::{
    process_decrypt, process_encrypt, process_gen_key, process_sign, process_verify, CmdExecutor,
};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::fmt;
use std::fmt::Formatter;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExecutor)]
pub enum TextSubCommand {
    #[command(about = "Sign a massage with a private/shared key")]
    Sign(TextSignOpts),

    #[command(about = "Verify a signed massage")]
    Verify(TextVerifyOpts),

    #[command(about = "Generate a new key")]
    GenKey(TextGenKeyOpts),

    #[command(about = "Encrypt the text")]
    Encrypt(TextEncryptOpts),

    #[command(about = "Decrypt the text by chacha2-opoly1305 ")]
    Decrypt(TextDecryptOpts),
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value ="black3" ,value_parser=parser_sign_format )]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextGenKeyOpts {
    #[arg(long, default_value ="black3" ,value_parser=parser_sign_format )]
    pub format: TextSignFormat,
    #[arg(short, long,value_parser=verify_path)]
    pub output: PathBuf,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value ="black3" ,value_parser=parser_sign_format )]
    pub format: TextSignFormat,

    #[arg(short, long)]
    pub sig: String,
}

#[derive(Debug, Parser)]
pub struct TextEncryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub key: String,

    #[arg(long, default_value ="chacha20poly1305" ,value_parser=parse_encrypt_format )]
    pub format: TextEncryptFormat,
}

#[derive(Debug, Parser)]
pub struct TextDecryptOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub key: String,

    #[arg(long, default_value ="chacha20poly1305" ,value_parser=parse_encrypt_format )]
    pub format: TextEncryptFormat,
}

#[derive(Debug, Copy, Clone)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}
#[derive(Debug, Copy, Clone)]
pub enum TextEncryptFormat {
    Chacha20Poly1305,
    // !todo:Supports more encryption and decryption modes
}

fn parser_sign_format(format: &str) -> anyhow::Result<TextSignFormat> {
    format.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "black3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            _ => Err(anyhow::anyhow!("Invalid sign/verify  format")),
        }
    }
}

impl From<TextSignFormat> for &str {
    fn from(format: TextSignFormat) -> Self {
        match format {
            TextSignFormat::Blake3 => "black3",
            TextSignFormat::Ed25519 => "ed25519",
        }
    }
}

impl fmt::Display for TextSignFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}

fn parse_encrypt_format(format: &str) -> anyhow::Result<TextEncryptFormat> {
    format.parse()
}

impl FromStr for TextEncryptFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chacha20poly1305" => Ok(TextEncryptFormat::Chacha20Poly1305),
            _ => Err(anyhow::anyhow!("Invalid encrypt/decrypt format")),
        }
    }
}

impl From<TextEncryptFormat> for &str {
    fn from(format: TextEncryptFormat) -> Self {
        match format {
            TextEncryptFormat::Chacha20Poly1305 => "chacha20poly1305",
        }
    }
}

impl fmt::Display for TextEncryptFormat {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}

impl CmdExecutor for TextSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let sig = process_sign(&self.input, &self.key, self.format)?;
        println!("{}", sig);
        Ok(())
    }
}

impl CmdExecutor for TextVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let verify = process_verify(&self.input, &self.key, &self.sig, self.format)?;
        println!("{}", verify);
        Ok(())
    }
}

impl CmdExecutor for TextGenKeyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let key = process_gen_key(self.format)?;
        match self.format {
            TextSignFormat::Blake3 => {
                let name = self.output.join("blake3.txt");
                tokio::fs::write(name, &key[0]).await?;
                Ok(())
            }
            TextSignFormat::Ed25519 => {
                let name = &self.output;
                tokio::fs::write(name.join("ed25519.sk"), &key[0]).await?;
                tokio::fs::write(name.join("ed25519.pk"), &key[1]).await?;
                Ok(())
            }
        }
    }
}

impl CmdExecutor for TextEncryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        match self.format {
            TextEncryptFormat::Chacha20Poly1305 => {
                let ciphertext = process_encrypt(&self.input, &self.key, self.format)?;
                println!("{}", ciphertext);
                Ok(())
            }
        }
    }
}

impl CmdExecutor for TextDecryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        match self.format {
            TextEncryptFormat::Chacha20Poly1305 => {
                let plaintext = process_decrypt(&self.input, &self.key, self.format)?;
                println!("{}", plaintext);
                Ok(())
            }
        }
    }
}
