// rcli csv -i input.csv -o output.json

use clap::Parser;
use rcli::{process_csv, Opts, SubCommand};

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opt) => process_csv(&opt.input, &opt.output)?,
    }
    Ok(())
}
