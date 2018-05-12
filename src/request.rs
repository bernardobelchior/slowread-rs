extern crate http;

use http::{Request, header::HeaderValue};

pub fn create_default_request(address: &str) -> Request<()> {
    let mut request = Request::get(address)
        .header("User-Agent", "rust")
        .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Connection", "Keep-Alive")
        .header("Cache-Control", "no-cache")
        .body(())
        .unwrap();

    let host = request.uri().authority_part().unwrap().host().to_string();
    request.headers_mut().insert("Host", HeaderValue::from_str(&host).unwrap());

    request
}

pub fn create_request_str(req: &Request<()>) -> String {
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

    req_str
}
