use crate::cli::verify_file;
use crate::cli::verify_path;
use crate::{process_gen_key, process_sign, process_verify, CmdExecutor};
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

impl CmdExecutor for TextSubCommand {
    async fn execute(self) -> anyhow::Result<()> {
        match self {
            TextSubCommand::Sign(opts) => opts.execute().await,
            TextSubCommand::Verify(opts) => opts.execute().await,
            TextSubCommand::GenKey(opts) => opts.execute().await,
        }
    }
}
