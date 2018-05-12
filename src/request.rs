extern crate http;

use http::{Request as Req, header::HeaderValue, uri::Scheme};
use std::net::{SocketAddr, IpAddr};
use trust_dns_resolver::Resolver;

pub struct Request {
    request: Req<()>,
    request_str: String,
    sock_addr: SocketAddr,
}

impl Request {
    pub fn new(address: &str, pipeline_factor: usize) -> Request {
        let mut request = Req::get(address)
            .header("User-Agent", "rust")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Connection", "Keep-Alive")
            .header("Cache-Control", "no-cache")
            .body(())
            .unwrap();

        let host = request.uri().authority_part().unwrap().host().to_string();
        request.headers_mut().insert("Host", HeaderValue::from_str(&host).unwrap());

        let request_str = Request::create_request_str(&request, pipeline_factor);
        let sock_addr = Request::generate_socket_addr(&request);

        Request {
            request,
            request_str,
            sock_addr,
        }
    }

    pub fn host(&self) -> &str {
        self.request.uri().authority_part().unwrap().host()
    }

    pub fn sock_addr(&self) -> &SocketAddr {
        &self.sock_addr 
    }

    pub fn scheme(&self) -> &Scheme {
        &self.request.uri().scheme_part().unwrap()
    }

    pub fn request_str(&self) -> &str {
        &self.request_str
    }

    fn generate_socket_addr(request: &Req<()>) -> SocketAddr {
        let port = if request.uri().scheme_part().unwrap() == &Scheme::HTTPS {
            443
        } else {
            80
        };

        let host = request.uri().authority_part().unwrap().host();
        let resolver = Resolver::from_system_conf().unwrap();
        let response = resolver.lookup_ip(host);

        if response.is_err() {
            let error = response.unwrap_err();
            panic!(
                "Error resolving host \"{}\". \n{}\nAborting execution...",
                host, error
                );
        }

        let ip_addr_option: Option<IpAddr> = response.unwrap().iter().next();

        if ip_addr_option.is_none() {
            panic!(
                "The address \"{}\" resolved to zero IP addresses. Aborting execution...",
                host
                );
        }

        SocketAddr::new(ip_addr_option.unwrap(), port)
    }


    fn create_request_str(req: &Req<()>, pipeline_factor: usize) -> String {
        let mut req_str = String::new();

        req_str.push_str(req.method().as_str());
        req_str.push_str(" ");
        req_str.push_str(req.uri().path());
        req_str.push_str(" HTTP/1.1\r\n");

        req.headers().iter().for_each(|(name, value)| {
            req_str.push_str(name.as_str());
            req_str.push_str(": ");
            req_str.push_str(value.to_str().unwrap());
            req_str.push_str("\r\n");
        });

        req_str.push_str("\r\n");

        req_str.repeat(pipeline_factor)
    }
}

