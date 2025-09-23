use alpha_p2p::Network;
use clap::Parser;
use directories::ProjectDirs;
use std::net;
use std::path::PathBuf;
use tracing::{debug, info};
use tracing_subscriber::fmt::time::ChronoUtc;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[derive(Parser)]
#[command(name = "Unicity PoW Migrator")]
#[command(about = "A lightweight peer for the Unicity PoW network, which helps to migrate UTXOs from PoW to Prism.", long_about = None)]
struct Args {
    /// Connect to specific peers.
    #[arg(option, short = 'c', long = "connect")]
    pub connect: Vec<net::SocketAddr>,

    /// Listen for incoming connections on the specified address/port.
    #[arg(option, short = 'l', long = "listen")]
    pub listen: Vec<net::SocketAddr>,

    /// Use the specified network (mainnet, testnet, regtest).
    #[arg(short, long, default_value = "testnet")]
    pub network: Network,

    /// Only connect to IPv4 peers.
    #[arg(long, conflicts_with = "ipv6_only", default_value = "false")]
    pub ipv4_only: bool,

    /// Only connect to IPv6 peers.
    #[arg(long, conflicts_with = "ipv4_only", default_value = "false")]
    pub ipv6_only: bool,

    /// Prefer IPv6 connections when both IPv4 and IPv6 are available.
    #[arg(long, default_value = "false")]
    pub prefer_ipv6: bool,

    /// Maximum number of connections to maintain.
    #[arg(default_value = 8)]
    pub max_connections: usize,

    /// Only connect to the specified peers and do not accept incoming connections.
    #[arg(default_value = false)]
    pub connect_only: bool,

    /// Directory to store data.
    #[arg(short, long)]
    pub datadir: Option<PathBuf>,

    /// Enable verbose logging.
    #[arg(short, long, default_value = "false")]
    pub verbose: bool,

    /// Log level (error, warn, info, debug, trace).
    #[arg(long, default_value_t = tracing::Level::INFO, value_parser = ["error", "warn", "info", "debug", "trace"])]
    pub log_level: tracing::Level,

    /// Start syncing from the specified block height.
    #[arg(long, default_value = 0)]
    pub start_height: u32,

    /// Number of blocks to sync before exiting (0 means sync indefinitely).
    #[arg(long, default_value = 0)]
    pub max_blocks: u32,

    /// User agent string to identify the client.
    #[arg(long, default_value = "PrismMigrator:0.1.0")]
    pub user_agent: String,

    /// Disable DNS seed lookups.
    #[arg(long, default_value = false)]
    pub no_dns_seeds: bool,

    /// Disable colored output.
    #[arg(long, default_value = false)]
    pub no_color: bool,
}

impl Args {
    fn data_dir(&self) -> PathBuf {
        self.datadir.clone().unwrap_or_else(|| {
            ProjectDirs::from("com", "unicity-labs", "prism-migrator")
                .map(|proj_dirs| proj_dirs.data_dir().to_path_buf())
                .unwrap_or_else(|| {
                    // Fallback if ProjectDirs fails, for whatever reason.
                    std::env::current_dir()
                        .unwrap_or_else(|_| PathBuf::from("."))
                        .join(".prism-migrator")
                })
        })
    }

    fn should_connect_to_peer(&self, addr: &net::SocketAddr) -> bool {
        match addr {
            net::SocketAddr::V4(_) => !self.ipv6_only,
            net::SocketAddr::V6(_) => !self.ipv4_only,
        }
    }

    fn filter_peers(&self, peers: Vec<net::SocketAddr>) -> Vec<net::SocketAddr> {
        let mut filtered: Vec<net::SocketAddr> = peers
            .into_iter()
            .filter(|addr| self.should_connect_to_peer(addr))
            .collect();

        if !self.ipv4_only && !self.ipv6_only && self.prefer_ipv6 {
            filtered.sort_by(|a, b| match (a, b) {
                (net::SocketAddr::V6(_), net::SocketAddr::V4(_)) => std::cmp::Ordering::Less,
                (net::SocketAddr::V4(_), net::SocketAddr::V6(_)) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            });
        }

        filtered
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    init_tracing(&args)?;

    Ok(())
}

fn init_tracing(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    // Which crates to filter with fallback
    let env_filter = EnvFilter::builder()
        .with_default_directive(args.log_level.into())
        .from_env_lossy()
        .add_directive("tokio=warn".parse()?);

    let use_ansi = std::io::IsTerminal::is_terminal(&std::io::stderr()) && !args.no_color;

    let subscriber = Registry::default().with(env_filter).with(
        tracing_subscriber::fmt::layer()
            .with_level(true)
            .with_target(true)
            .with_thread_ids(args.verbose)
            .with_thread_names(args.verbose)
            .with_ansi(use_ansi)
            .with_file(args.verbose)
            .with_line_number(args.verbose)
            .with_timer(ChronoUtc::rfc_3339()),
    );

    subscriber.try_init()?;

    debug!("Starting Prism Migrator with level: {}", level);

    Ok(())
}
