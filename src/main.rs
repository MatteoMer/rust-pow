use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Node,
    Miner,
}

fn run_node() {}

fn run_miner() {}

fn main() {
    let args = Args::parse();
    match args.cmd {
        Commands::Node => run_node(),
        Commands::Miner => run_miner(),
    }
}
