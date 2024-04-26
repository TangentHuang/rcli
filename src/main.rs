// rcli csv -i input.csv -o output.json

use clap::Parser;
use rcli::{CmdExecutor, Opts};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Opts::parse();
    let cmd = opts.cmd;
    cmd.execute().await?;
    Ok(())
}
