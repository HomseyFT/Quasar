use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use clap::{Args, Parser, Subcommand};
use quasar::{
    event::{ConnectEvent, Event, ExecEvent},
    loader::{self, DropCounter},
    policy::{
        learn,
        sync::{manual_deny_count, MapSync},
        PolicySet,
    },
    registry::{Attribution, ContainerChange, Registry},
    sink::{
        jsonl::JsonlSink,
        ntfy::{self, Admit, Alert, AlertKey, NtfySink, Suppressor},
        record::{Body, Clock, Record},
        socket::{self, Client, Frame},
    },
};
use tokio::{io::unix::AsyncFd, sync::mpsc, time::MissedTickBehavior};

/// Bounded so a container in a crash-loop cannot grow the queue without limit.
/// Overflow is counted and reported rather than allowed to stall the drain.
const EVENT_QUEUE_DEPTH: usize = 4096;

/// Small on purpose. Suppression means a healthy system produces a trickle, so
/// a full queue means ntfy is unreachable and the backlog is already stale.
const ALERT_QUEUE_DEPTH: usize = 256;

/// The log is buffered, so it is only durable as far as the last flush. This
/// bounds what a SIGKILL or a power loss can take with it -- an audit trail
/// that loses its last few thousand records is not one.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Parser)]
#[command(name = "quasar", version, about = "eBPF container security monitor")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Attach the probes and stream events to stdout.
    Run(RunArgs),

    /// Attach to a running daemon and watch what it sees.
    Top {
        /// The daemon's socket.
        #[arg(long, value_name = "PATH", default_value = socket::DEFAULT_SOCKET)]
        socket: PathBuf,
    },

    /// Turn an observed log into draft policy files.
    ///
    /// Re-runnable: manual entries are never touched, so correcting a file by
    /// hand and learning again is the intended workflow.
    Learn {
        /// The JSONL log written by `run --jsonl`.
        #[arg(long, value_name = "PATH")]
        from: PathBuf,

        /// Policy directory to create or update.
        #[arg(long, default_value = "policy", value_name = "DIR")]
        out: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    match Cli::parse().command {
        Command::Run(args) => run(&args).await,
        Command::Top { socket } => top(&socket).await,
        Command::Learn { from, out } => learn_policy(&from, &out),
    }
}

/// Attach to a running daemon. Deliberately a separate process from the
/// monitor: this can be killed, backgrounded or run twenty times over without
/// the daemon noticing.
async fn top(path: &Path) -> Result<()> {
    let mut client = Client::connect(path).await?;
    eprintln!("quasar: attached to {}", path.display());

    while let Some(frame) = client.next().await? {
        match frame {
            Frame::Event { record } => println!("{}", describe(&record)),
            Frame::Stats { snapshot } => println!(
                "-- {} execs, {} connects, {} alerts across {} sources --",
                snapshot.total.execs,
                snapshot.total.connects,
                snapshot.total.alerts,
                snapshot.by_source.len()
            ),
            // The gap is shown rather than hidden: a live view that looks
            // continuous when it is not is worse than one that admits it.
            Frame::Lagged { missed } => {
                println!("-- fell behind, {missed} events missed --");
            }
        }
    }

    eprintln!("quasar: the daemon closed the connection");
    Ok(())
}

fn describe(record: &Record) -> String {
    let what = match &record.body {
        Body::Exec { path } => format!("exec {path}"),
        Body::Connect { proto, dest, port } => format!("connect {proto} {dest}:{port}"),
    };
    format!(
        "[{}] {:<24} pid={} uid={} comm={} {what}",
        record.time, record.source, record.pid, record.uid, record.comm
    )
}

fn learn_policy(from: &Path, out: &Path) -> Result<()> {
    let observations = learn::observe(from)?;
    let summary = learn::merge_into(&observations, out)?;

    println!(
        "read {} events: {} named, {} unattributable, {} malformed",
        observations.total,
        observations.total - observations.unattributable - observations.malformed_lines,
        observations.unattributable,
        observations.malformed_lines,
    );
    println!(
        "{} containers: {} exec rules and {} egress rules added, {} already covered",
        summary.containers, summary.exec_added, summary.egress_added, summary.already_covered,
    );
    if observations.unstable_paths > 0 {
        println!(
            "{} execs through an unstable /proc path not baselined (runc container init)",
            observations.unstable_paths,
        );
    }
    println!("wrote {}", out.display());
    println!("review with: git diff {}", out.display());

    Ok(())
}

#[derive(Args)]
struct RunArgs {
    /// Relocate against this BTF blob instead of the running kernel.
    #[arg(long, value_name = "PATH")]
    btf: Option<PathBuf>,

    /// Docker endpoint. Defaults to the local unix socket; pass a
    /// host:port to use docker-socket-proxy instead.
    #[arg(long, value_name = "ENDPOINT")]
    docker: Option<String>,

    /// Also append every event to this durable JSONL log.
    #[arg(long, value_name = "PATH")]
    jsonl: Option<PathBuf>,

    /// Push these policy files into the kernel, so allowed events are
    /// filtered in the probe and never reach userspace.
    #[arg(long, value_name = "DIR")]
    policy: Option<PathBuf>,

    /// Push an alert to this ntfy topic URL for anything denied or
    /// unbaselined. Without it quasar observes and logs but never notifies.
    #[arg(long, value_name = "URL")]
    ntfy: Option<String>,

    /// Serve a live event tail and counters on this unix socket for
    /// `quasar top`. Without it the daemon has no socket at all.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,

    /// Do not print events. The JSONL log and every diagnostic on stderr are
    /// unaffected. stdout is line buffered, so a syscall per event is real
    /// cost at pihole's rates -- an unattended run should not pay it.
    #[arg(long)]
    quiet: bool,
}

async fn run(args: &RunArgs) -> Result<()> {
    let btf = args.btf.as_deref();
    let docker = args.docker.as_deref();
    let jsonl = args.jsonl.as_deref();
    let policy_dir = args.policy.as_deref();
    let quiet = args.quiet;
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

    // Policy goes down before the ring buffers are drained, so a known-good
    // event is already being filtered by the time the first one could arrive.
    let policies = Arc::new(match policy_dir {
        Some(dir) => PolicySet::load_dir(dir)?,
        None => PolicySet::default(),
    });
    let mut sync = MapSync::take(&mut exec_ebpf, &mut connect_ebpf)?;

    let exec_kernel_drops = DropCounter::take(&mut exec_ebpf, "exec")?;
    let connect_kernel_drops = DropCounter::take(&mut connect_ebpf, "connect")?;

    // Separate buffers, so a flood of udp_sendmsg cannot starve the exec
    // stream. They are drained independently and merged onto one channel.
    let exec_map = exec_ebpf
        .take_map("exec_events")
        .context("no exec_events map in the exec object")?;
    let mut exec_ring = AsyncFd::new(RingBuf::try_from(exec_map)?)?;

    let connect_map = connect_ebpf
        .take_map("connect_events")
        .context("no connect_events map in the connect object")?;
    let mut connect_ring = AsyncFd::new(RingBuf::try_from(connect_map)?)?;

    // Attribution can await a Docker round trip, which must never stall the
    // ring buffer drain -- the kernel would overwrite records while we waited.
    let (tx, mut rx) = mpsc::channel::<Event>(EVENT_QUEUE_DEPTH);

    sync_all(&mut sync, &policies, &registry).await;

    let (changes_tx, mut changes_rx) = mpsc::channel::<ContainerChange>(64);

    // A container's cgroup id changes every time it starts, so its allowlist
    // has to be rewritten under the new id or nothing matches.
    let resync = tokio::spawn({
        let policies = Arc::clone(&policies);
        async move {
            while let Some(change) = changes_rx.recv().await {
                match change {
                    ContainerChange::Started { name, cgroup_id } => {
                        if let Some(policy) = policies.by_container.get(&name) {
                            let applied = sync.apply(cgroup_id, policy);
                            eprintln!(
                                "quasar: {name} started, {} exec and {} egress rules applied",
                                applied.exec, applied.egress
                            );
                        }
                    }
                    ContainerChange::Stopped { name, cgroup_id } => {
                        if let Some(policy) = policies.by_container.get(&name) {
                            sync.clear(cgroup_id, policy);
                        }
                    }
                }
            }
        }
    });

    let mut sink = jsonl.map(JsonlSink::create).transpose()?;
    let clock = Clock::new()?;

    // Attaching, killing or multiplying clients must not change what the
    // monitor does, so the server is started once and never awaited on.
    let publisher = args
        .socket
        .as_deref()
        .map(socket::serve)
        .transpose()?
        .inspect(|_| {
            eprintln!(
                "quasar: serving {}",
                args.socket.as_deref().unwrap_or(Path::new("")).display()
            );
        });

    let alert_drops = Arc::new(AtomicU64::new(0));
    let alerts = spawn_alerter(args.ntfy.as_deref(), Arc::clone(&alert_drops))?;

    let consumer = tokio::spawn({
        let registry = Arc::clone(&registry);
        let policies = Arc::clone(&policies);
        let alert_drops = Arc::clone(&alert_drops);
        async move {
            let mut flush = tokio::time::interval(FLUSH_INTERVAL);
            flush.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                let event = tokio::select! {
                    received = rx.recv() => match received {
                        Some(event) => event,
                        None => break,
                    },
                    _ = flush.tick() => {
                        if let Some(Err(error)) = sink.as_mut().map(JsonlSink::flush) {
                            eprintln!("quasar: flushing the log failed: {error:#}");
                        }
                        continue;
                    }
                };

                let who = registry.resolve(event.cgroup_id(), event.pid()).await;

                let alert = alert_for(&policies, &who, &event);
                let alerted = alert.is_some();

                if let (Some(tx), Some(alert)) = (&alerts, alert) {
                    // An alert that cannot be queued is dropped rather than
                    // allowed to stall event processing, and counted so the
                    // loss is not silent.
                    if tx.try_send(alert).is_err() {
                        alert_drops.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Built once. The log and the socket serve the same value, so
                // they cannot disagree about what happened.
                let record = match &event {
                    Event::Exec(e) => clock.exec(&who, e),
                    Event::Connect(e) => clock.connect(&who, e),
                };

                // A log write that fails must not take the monitor down, but it
                // must not pass unnoticed either.
                if let Some(Err(error)) = sink.as_mut().map(|s| s.write(&record)) {
                    eprintln!("quasar: log write failed: {error:#}");
                }

                if let Some(publisher) = &publisher {
                    publisher.publish(&record, alerted);
                }
                if !quiet {
                    match event {
                        Event::Exec(e) => print_exec(&who, &e),
                        Event::Connect(e) => print_connect(&who, &e),
                    }
                }
            }
            if let Some(Err(error)) = sink.as_mut().map(JsonlSink::flush) {
                eprintln!("quasar: flushing the log failed: {error:#}");
            }
        }
    });

    let watcher = tokio::spawn({
        let registry = Arc::clone(&registry);
        async move { registry.watch(Some(changes_tx)).await }
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
    resync.abort();

    report_losses(dropped, &exec_kernel_drops, &connect_kernel_drops);
    let missed = alert_drops.load(Ordering::Relaxed);
    if missed > 0 {
        eprintln!("quasar: {missed} alerts were never sent, ntfy could not keep up");
    }
    eprintln!("quasar: detaching");
    Ok(())
}

/// The alert path, kept off the consumer: a POST to an unreachable ntfy blocks
/// for its whole timeout, and event processing must not wait on that.
fn spawn_alerter(url: Option<&str>, drops: Arc<AtomicU64>) -> Result<Option<mpsc::Sender<Alert>>> {
    let Some(url) = url else {
        return Ok(None);
    };

    let sink = NtfySink::new(url)?;
    let (tx, mut rx) = mpsc::channel::<Alert>(ALERT_QUEUE_DEPTH);

    tokio::spawn(async move {
        let mut suppressor = Suppressor::new(ntfy::DEFAULT_WINDOW);
        let mut sweep = tokio::time::interval_at(
            tokio::time::Instant::now() + ntfy::DEFAULT_WINDOW,
            ntfy::DEFAULT_WINDOW,
        );
        sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                received = rx.recv() => {
                    let Some(alert) = received else { break };
                    if let Admit::Send { suppressed } =
                        suppressor.admit(&alert.key, Instant::now())
                    {
                        push(&sink, &alert.render(suppressed), &drops).await;
                    }
                }
                _ = sweep.tick() => {
                    // Tell someone about the tail of a burst that stopped.
                    // Without this an alert fires once and the ten thousand
                    // behind it are never mentioned.
                    for (key, suppressed) in suppressor.expired(Instant::now()) {
                        push(&sink, &ntfy::render(&key, "", suppressed), &drops).await;
                    }
                }
            }
        }
    });

    Ok(Some(tx))
}

async fn push(sink: &NtfySink, message: &ntfy::Message, drops: &AtomicU64) {
    if let Err(error) = sink.send(message).await {
        drops.fetch_add(1, Ordering::Relaxed);
        eprintln!("quasar: alert not delivered: {error:#}");
    }
}

/// The alert an event deserves, or `None` for silence.
///
/// Only a named container can be matched to a policy file, so an event from an
/// unnamed one, from the host, or from a container with no policy is logged and
/// nothing more.
fn alert_for(policies: &PolicySet, who: &Attribution, event: &Event) -> Option<Alert> {
    let Attribution::Named { name, .. } = who else {
        return None;
    };

    let (decision, subject, detail) = match event {
        Event::Exec(e) => {
            let path = e.filename().into_owned();
            (
                policies.exec_alert(name, &path)?,
                format!("exec {path}"),
                detail(e.pid, e.ppid, e.uid, &e.comm()),
            )
        }
        Event::Connect(e) => (
            policies.egress_alert(name, e.destination())?,
            format!(
                "connect {} {}:{}",
                e.protocol_name(),
                e.destination(),
                e.dport
            ),
            detail(e.pid, e.ppid, e.uid, &e.comm()),
        ),
    };

    Some(Alert {
        key: AlertKey {
            container: name.clone(),
            decision,
            subject,
        },
        detail,
    })
}

fn detail(pid: u32, ppid: u32, uid: u32, comm: &str) -> String {
    format!("pid {pid} ppid {ppid} uid {uid} comm {comm}")
}

/// Two different losses with two different fixes, so they are never summed.
/// A kernel drop means the ring buffer was too small for the burst; a queue
/// drop means attribution could not keep up with the drain.
fn report_losses(queue_drops: u64, exec: &DropCounter, connect: &DropCounter) {
    let (exec, connect) = (exec.total(), connect.total());

    if exec + connect > 0 {
        eprintln!(
            "quasar: {} events dropped in the kernel, ring buffer full \
             (exec={exec}, connect={connect})",
            exec + connect
        );
    }
    if queue_drops > 0 {
        eprintln!(
            "quasar: {queue_drops} events dropped in userspace, \
             attribution could not keep up"
        );
    }
}

/// Push every loaded policy down under the cgroup id its container is running
/// as right now. A container with no policy is simply not filtered.
async fn sync_all(sync: &mut MapSync, policies: &PolicySet, registry: &Registry) {
    if policies.by_container.is_empty() {
        return;
    }

    let mut synced = 0;
    let mut denies = 0;
    for (name, cgroup_id) in registry.running_containers().await {
        let Some(policy) = policies.by_container.get(&name) else {
            continue;
        };
        let applied = sync.apply(cgroup_id, policy);
        if applied.rejected > 0 {
            eprintln!(
                "quasar: {name}: {} rules would not fit in the allowlist maps",
                applied.rejected
            );
        }
        denies += manual_deny_count(policy);
        synced += 1;
    }

    eprintln!(
        "quasar: policy loaded for {} of {} containers ({} running)",
        synced,
        policies.by_container.len(),
        registry.running_containers().await.len(),
    );
    if denies > 0 {
        // Deny rules deliberately do not go into the maps: a denied event has
        // to reach userspace to be alerted on.
        eprintln!("quasar: {denies} manual deny rules are enforced in userspace, not the kernel");
    }
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
