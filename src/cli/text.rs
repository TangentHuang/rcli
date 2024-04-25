use crate::cli::verify_file;
use crate::cli::verify_path;
use clap::Parser;
use std::fmt;
use std::fmt::Formatter;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Parser)]
pub enum TextSubCommand {
    #[command(about = "Sign a massage with a private/shared key")]
    Sign(TextSignOpts),

    #[command(about = "Verify a signed massage")]
    Verify(TextVerifyOpts),

    #[command(about = "Generate a newkey")]
    GenKey(TextGenKeyOpts),
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,

    #[arg(short, long, value_parser = verify_file)]
    pub key: String,

    #[arg(long, default_value ="black3" ,value_parser=parser_format )]
    pub format: TextSignFormat,
}

#[derive(Debug, Parser)]
pub struct TextGenKeyOpts {
    #[arg(long, default_value ="black3" ,value_parser=parser_format )]
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

    #[arg(long, default_value ="black3" ,value_parser=parser_format )]
    pub format: TextSignFormat,

    #[arg(short, long)]
    pub sig: String,
}

#[derive(Debug, Copy, Clone)]
pub enum TextSignFormat {
    Blake3,
    Ed25519,
}

fn parser_format(format: &str) -> anyhow::Result<TextSignFormat> {
    format.parse()
}

impl FromStr for TextSignFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "black3" => Ok(TextSignFormat::Blake3),
            "ed25519" => Ok(TextSignFormat::Ed25519),
            _ => Err(anyhow::anyhow!("Invalid  format")),
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
