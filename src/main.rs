use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use clap::{Parser, Subcommand};
use quasar::{event::ExecEvent, loader};
use tokio::io::unix::AsyncFd;

#[derive(Parser)]
#[command(name = "quasar", version, about = "eBPF container security monitor")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Attach the probes and stream events to stdout.
    Run {
        /// Relocate against this BTF blob instead of the running kernel.
        #[arg(long, value_name = "PATH")]
        btf: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    match Cli::parse().command {
        Command::Run { btf } => run(btf.as_deref()).await,
    }
}

async fn run(btf: Option<&Path>) -> Result<()> {
    let mut ebpf = loader::load_exec(btf)?;
    loader::attach_exec(&mut ebpf)?;

    let events = ebpf
        .map_mut("events")
        .context("no events map in the exec object")?;
    let mut ring = AsyncFd::new(RingBuf::try_from(events)?)?;

    eprintln!("quasar: attached to sched:sched_process_exec, ctrl-c to stop");

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("waiting for ctrl-c")?;
                break;
            }
            readable = ring.readable_mut() => {
                let mut guard = readable.context("polling the ring buffer")?;
                let ring = guard.get_inner_mut();
                while let Some(record) = ring.next() {
                    match ExecEvent::from_bytes(&record) {
                        Some(event) => print_exec(&event),
                        None => eprintln!(
                            "quasar: dropped a {}-byte ring buffer record, too short for an \
                             exec_event -- probe and loader disagree about the format",
                            record.len()
                        ),
                    }
                }
                guard.clear_ready();
            }
        }
    }

    eprintln!("quasar: detaching");
    Ok(())
}

fn print_exec(e: &ExecEvent) {
    println!(
        "[{:>14.6}] cgroup={} pid={} tgid={} ppid={} uid={} gid={} comm={} file={}",
        e.timestamp_ns as f64 / 1e9,
        e.cgroup_id,
        e.pid,
        e.tgid,
        e.ppid,
        e.uid,
        e.gid,
        e.comm(),
        e.filename(),
    );
}
