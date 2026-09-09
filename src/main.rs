use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use clap::{Parser, Subcommand};
use quasar::{
    event::{ConnectEvent, Event, ExecEvent},
    loader,
    registry::{Attribution, Registry},
};
use tokio::{io::unix::AsyncFd, sync::mpsc};

/// Bounded so a container in a crash-loop cannot grow the queue without limit.
/// Overflow is counted and reported rather than allowed to stall the drain.
const EVENT_QUEUE_DEPTH: usize = 4096;

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

        /// Docker endpoint. Defaults to the local unix socket; pass a
        /// host:port to use docker-socket-proxy instead.
        #[arg(long, value_name = "ENDPOINT")]
        docker: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    match Cli::parse().command {
        Command::Run { btf, docker } => run(btf.as_deref(), docker.as_deref()).await,
    }
}

async fn run(btf: Option<&Path>, docker: Option<&str>) -> Result<()> {
    let mut exec_ebpf = loader::load_exec(btf)?;
    loader::attach_exec(&mut exec_ebpf)?;

    let mut connect_ebpf = loader::load_connect(btf)?;
    loader::attach_connect(&mut connect_ebpf)?;

    // A registry that cannot reach Docker still resolves container ids, so an
    // unreachable daemon degrades the output rather than stopping the monitor.
    let registry = Arc::new(match Registry::connect(docker).await {
        Ok(registry) => registry,
        Err(error) => {
            eprintln!("quasar: Docker unavailable ({error:#}); events will not be named");
            Registry::offline()
        }
    });

    // Separate buffers, so a flood of udp_sendmsg cannot starve the exec
    // stream. They are drained independently and merged onto one channel.
    let exec_map = exec_ebpf
        .map_mut("exec_events")
        .context("no exec_events map in the exec object")?;
    let mut exec_ring = AsyncFd::new(RingBuf::try_from(exec_map)?)?;

    let connect_map = connect_ebpf
        .map_mut("connect_events")
        .context("no connect_events map in the connect object")?;
    let mut connect_ring = AsyncFd::new(RingBuf::try_from(connect_map)?)?;

    // Attribution can await a Docker round trip, which must never stall the
    // ring buffer drain -- the kernel would overwrite records while we waited.
    let (tx, mut rx) = mpsc::channel::<Event>(EVENT_QUEUE_DEPTH);

    let consumer = tokio::spawn({
        let registry = Arc::clone(&registry);
        async move {
            while let Some(event) = rx.recv().await {
                let who = registry.resolve(event.cgroup_id(), event.pid()).await;
                match event {
                    Event::Exec(e) => print_exec(&who, &e),
                    Event::Connect(e) => print_connect(&who, &e),
                }
            }
        }
    });

    let watcher = tokio::spawn({
        let registry = Arc::clone(&registry);
        async move { registry.watch().await }
    });

    eprintln!(
        "quasar: attached to sched:sched_process_exec and \
         fentry on tcp_v4_connect/tcp_v6_connect/udp_sendmsg, ctrl-c to stop"
    );

    let mut dropped: u64 = 0;
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("waiting for ctrl-c")?;
                break;
            }
            readable = exec_ring.readable_mut() => {
                let mut guard = readable.context("polling the exec ring buffer")?;
                drain(guard.get_inner_mut(), decode_exec, &tx, &mut dropped);
                guard.clear_ready();
            }
            readable = connect_ring.readable_mut() => {
                let mut guard = readable.context("polling the connect ring buffer")?;
                drain(guard.get_inner_mut(), decode_connect, &tx, &mut dropped);
                guard.clear_ready();
            }
        }
    }

    drop(tx);
    let _ = consumer.await;
    watcher.abort();

    if dropped > 0 {
        eprintln!("quasar: {dropped} events dropped, attribution could not keep up");
    }
    eprintln!("quasar: detaching");
    Ok(())
}

fn decode_exec(bytes: &[u8]) -> Option<Event> {
    ExecEvent::from_bytes(bytes).map(|e| Event::Exec(Box::new(e)))
}

fn decode_connect(bytes: &[u8]) -> Option<Event> {
    ConnectEvent::from_bytes(bytes).map(Event::Connect)
}

/// Move everything currently in a ring buffer onto the channel. Decoding is
/// the only work done here; anything that could block belongs downstream.
fn drain<T>(
    ring: &mut RingBuf<T>,
    decode: fn(&[u8]) -> Option<Event>,
    tx: &mpsc::Sender<Event>,
    dropped: &mut u64,
) {
    while let Some(record) = ring.next() {
        let Some(event) = decode(&record) else {
            eprintln!(
                "quasar: dropped a {}-byte ring buffer record, too short for its event type \
                 -- probe and loader disagree about the format",
                record.len()
            );
            continue;
        };
        if tx.try_send(event).is_err() {
            *dropped += 1;
        }
    }
}

fn print_connect(who: &Attribution, e: &ConnectEvent) {
    println!(
        "[{:>14.6}] {:<24} pid={} ppid={} uid={} comm={} {}->{}:{}{}",
        e.timestamp_ns as f64 / 1e9,
        who.to_string(),
        e.pid,
        e.ppid,
        e.uid,
        e.comm(),
        e.protocol_name(),
        e.destination(),
        e.dport,
        if who.is_unknown() {
            "  [unattributed]"
        } else {
            ""
        },
    );
}

fn print_exec(who: &Attribution, e: &ExecEvent) {
    println!(
        "[{:>14.6}] {:<24} pid={} ppid={} uid={} comm={} file={}{}",
        e.timestamp_ns as f64 / 1e9,
        who.to_string(),
        e.pid,
        e.ppid,
        e.uid,
        e.comm(),
        e.filename(),
        // A host process is an ordinary, fully explained outcome and needs no
        // marker. Only a genuine attribution failure is worth flagging.
        if who.is_unknown() {
            "  [unattributed]"
        } else {
            ""
        },
    );
}
