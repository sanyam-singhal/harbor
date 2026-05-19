use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpStream,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::browser) struct DemoHttpRequest {
    pub(in crate::browser) method: String,
    pub(in crate::browser) path: String,
    pub(in crate::browser) query: HashMap<String, String>,
    pub(in crate::browser) headers: HashMap<String, String>,
    pub(in crate::browser) body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::browser) struct DemoHttpResponse {
    pub(in crate::browser) status: u16,
    pub(in crate::browser) headers: Vec<(String, String)>,
    pub(in crate::browser) body: String,
}

pub(in crate::browser) fn read_http_request(
    stream: &mut TcpStream,
) -> Result<DemoHttpRequest, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    let mut scratch = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return Err("connection closed before request headers".into());
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > 128 * 1024 {
            return Err("request is too large".into());
        }
        if let Some(index) = find_header_end(&bytes) {
            break index;
        }
    };
    let headers_text = String::from_utf8(bytes[..header_end].to_vec())?;
    let mut lines = headers_text.split("\r\n");
    let request_line = lines.next().ok_or("missing request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().ok_or("missing method")?.to_owned();
    let target = request_parts.next().ok_or("missing target")?;
    let (path, query) = parse_target(target)?;
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let body_start = header_end + 4;
    let content_length = headers
        .get("content-length")
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    while bytes.len().saturating_sub(body_start) < content_length {
        let read = stream.read(&mut scratch)?;
        if read == 0 {
            return Err("connection closed before request body".into());
        }
        bytes.extend_from_slice(&scratch[..read]);
        if bytes.len() > 128 * 1024 {
            return Err("request is too large".into());
        }
    }
    let body_end = body_start + content_length;
    let body = String::from_utf8(bytes[body_start..body_end].to_vec())?;
    Ok(DemoHttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_target(
    target: &str,
) -> Result<(String, HashMap<String, String>), Box<dyn std::error::Error>> {
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), parse_form(query)?),
        None => (target.to_owned(), HashMap::new()),
    };
    Ok((path, query))
}

pub(in crate::browser) fn parse_form(
    body: &str,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut values = HashMap::new();
    if body.is_empty() {
        return Ok(values);
    }
    for pair in body.split('&') {
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        values.insert(percent_decode_form(name)?, percent_decode_form(value)?);
    }
    Ok(values)
}

fn percent_decode_form(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut bytes = Vec::with_capacity(value.len());
    let input = value.as_bytes();
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'+' => {
                bytes.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= input.len() {
                    return Err("truncated percent encoding".into());
                }
                let high = hex_value(input[index + 1]).ok_or("invalid percent encoding")?;
                let low = hex_value(input[index + 2]).ok_or("invalid percent encoding")?;
                bytes.push((high << 4) | low);
                index += 3;
            }
            byte => {
                bytes.push(byte);
                index += 1;
            }
        }
    }
    Ok(String::from_utf8(bytes)?)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(in crate::browser) fn url_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => {
                encoded.push('%');
                encoded.push(hex_digit(byte >> 4));
                encoded.push(hex_digit(byte & 0x0f));
            }
        }
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'A' + (value - 10)),
        _ => '0',
    }
}

pub(in crate::browser) fn html_response(
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
) -> DemoHttpResponse {
    DemoHttpResponse {
        status,
        headers,
        body,
    }
}

pub(in crate::browser) fn error_response(status: u16, message: &str) -> DemoHttpResponse {
    html_response(
        status,
        Vec::new(),
        format!(
            "<!doctype html><html><body><main><h1>{}</h1></main></body></html>",
            html_escape(message)
        ),
    )
}

pub(in crate::browser) fn redirect_response(
    status: u16,
    location: &str,
    set_cookie: Option<String>,
) -> DemoHttpResponse {
    let mut headers = vec![
        ("Location".to_owned(), location.to_owned()),
        ("Referrer-Policy".to_owned(), "no-referrer".to_owned()),
    ];
    if let Some(cookie) = set_cookie {
        headers.push(("Set-Cookie".to_owned(), cookie));
    }
    html_response(status, headers, String::new())
}

pub(in crate::browser) fn write_http_response(
    stream: &mut TcpStream,
    response: DemoHttpResponse,
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = match response.status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason,
        response.body.len()
    );
    for (name, value) in response.headers {
        head.push_str(&name);
        head.push_str(": ");
        head.push_str(&value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(response.body.as_bytes())?;
    stream.flush()?;
    Ok(())
}

pub(in crate::browser) fn html_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}
