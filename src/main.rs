// rcli csv -i input.csv -o output.json

use clap::Parser;
use rcli::{
    process_b64_decode, process_b64_encode, process_csv, process_gen_pass, Base64subCommand, Opts,
    SubCommand,
};

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opt) => {
            let output = if let Some(output) = opt.output {
                output.clone()
            } else {
                format!("output.{}", opt.format)
            };
            process_csv(&opt.input, &output, opt.format)?
        }
        SubCommand::GenPass(opt) => {
            process_gen_pass(
                opt.length,
                !opt.no_uppercase,
                !opt.no_lowercase,
                !opt.no_number,
                !opt.no_symbol,
            )?;
        }
        SubCommand::Base64(subcmd) => match subcmd {
            Base64subCommand::Encode(opt) => {
                process_b64_encode(&opt.input, opt.format)?;
            }
            Base64subCommand::Decode(opt) => {
                process_b64_decode(&opt.input, opt.format)?;
            }
        },
    }
    Ok(())
}
