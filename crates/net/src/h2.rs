// Copyright 2015-2018 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// https://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// https://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! TLS protocol related components for DNS over HTTPS (DoH)

use core::future::Future;
use core::net::SocketAddr;
use core::pin::Pin;
use core::str::FromStr;
use core::task::{Context, Poll};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use futures_util::stream::Stream;
use h2::client::SendRequest;
use http::header::{self, CONTENT_LENGTH};
use http::{Method, StatusCode};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::error::NetError;
use crate::http::{RequestContext, SetHeaders, Version, fetch_body, select_request_method};
use crate::proto::op::{DnsRequest, DnsResponse};
use crate::runtime::iocompat::AsyncIoStdAsTokio;
use crate::runtime::{DnsTcpStream, RuntimeProvider, Spawn};
use crate::xfer::{CONNECT_TIMEOUT, DnsExchange, DnsRequestSender, DnsResponseStream};

/// A DNS client connection for DNS-over-HTTPS
#[derive(Clone)]
#[must_use = "futures do nothing unless polled"]
pub struct HttpsClientStream {
    context: Arc<RequestContext>,
    h2: SendRequest<Bytes>,
    is_shutdown: bool,
}

impl HttpsClientStream {
    /// Constructs a new HttpsClientStreamBuilder with the associated ClientConfig
    pub fn builder<P: RuntimeProvider>(
        client_config: Arc<ClientConfig>,
        provider: P,
    ) -> HttpsClientStreamBuilder<P> {
        HttpsClientStreamBuilder {
            provider,
            client_config,
            bind_addr: None,
            set_headers: None,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

impl DnsRequestSender for HttpsClientStream {
    /// This indicates that the HTTP message was successfully sent, and we now have the response.RecvStream
    ///
    /// If the request fails, this will return the error, and it should be assumed that the Stream portion of
    ///   this will have no date.
    ///
    /// ```text
    /// RFC 8484              DNS Queries over HTTPS (DoH)          October 2018
    ///
    ///
    /// 4.2.  The HTTP Response
    ///
    ///    The only response type defined in this document is "application/dns-
    ///    message", but it is possible that other response formats will be
    ///    defined in the future.  A DoH server MUST be able to process
    ///    "application/dns-message" request messages.
    ///
    ///    Different response media types will provide more or less information
    ///    from a DNS response.  For example, one response type might include
    ///    information from the DNS header bytes while another might omit it.
    ///    The amount and type of information that a media type gives are solely
    ///    up to the format, which is not defined in this protocol.
    ///
    ///    Each DNS request-response pair is mapped to one HTTP exchange.  The
    ///    responses may be processed and transported in any order using HTTP's
    ///    multi-streaming functionality (see Section 5 of [RFC7540]).
    ///
    ///    Section 5.1 discusses the relationship between DNS and HTTP response
    ///    caching.
    ///
    /// 4.2.1.  Handling DNS and HTTP Errors
    ///
    ///    DNS response codes indicate either success or failure for the DNS
    ///    query.  A successful HTTP response with a 2xx status code (see
    ///    Section 6.3 of [RFC7231]) is used for any valid DNS response,
    ///    regardless of the DNS response code.  For example, a successful 2xx
    ///    HTTP status code is used even with a DNS message whose DNS response
    ///    code indicates failure, such as SERVFAIL or NXDOMAIN.
    ///
    ///    HTTP responses with non-successful HTTP status codes do not contain
    ///    replies to the original DNS question in the HTTP request.  DoH
    ///    clients need to use the same semantic processing of non-successful
    ///    HTTP status codes as other HTTP clients.  This might mean that the
    ///    DoH client retries the query with the same DoH server, such as if
    ///    there are authorization failures (HTTP status code 401; see
    ///    Section 3.1 of [RFC7235]).  It could also mean that the DoH client
    ///    retries with a different DoH server, such as for unsupported media
    ///    types (HTTP status code 415; see Section 6.5.13 of [RFC7231]), or
    ///    where the server cannot generate a representation suitable for the
    ///    client (HTTP status code 406; see Section 6.5.6 of [RFC7231]), and so
    ///    on.
    /// ```
    fn send_message(&mut self, mut request: DnsRequest) -> DnsResponseStream {
        if self.is_shutdown {
            panic!("can not send messages after stream is shutdown")
        }

        // per the RFC, a zero id allows for the HTTP packet to be cached better
        request.metadata.id = 0;
        let op_code = request.op_code;

        let bytes = match request.to_vec() {
            Ok(bytes) => bytes,
            Err(err) => return NetError::from(err).into(),
        };

        let method = select_request_method(op_code, bytes.len(), &self.context);

        Box::pin(send(
            self.h2.clone(),
            Bytes::from(bytes),
            self.context.clone(),
            method,
        ))
        .into()
    }

    fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }
}

impl Stream for HttpsClientStream {
    type Item = Result<(), NetError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.is_shutdown {
            return Poll::Ready(None);
        }

        // just checking if the connection is ok
        match self.h2.poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(()))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(NetError::from(format!(
                "h2 stream errored: {e}",
            ))))),
        }
    }
}

/// A HTTPS connection builder for DNS-over-HTTPS
#[derive(Clone)]
pub struct HttpsClientStreamBuilder<P> {
    provider: P,
    client_config: Arc<ClientConfig>,
    bind_addr: Option<SocketAddr>,
    set_headers: Option<Arc<dyn SetHeaders>>,
    connect_timeout: Duration,
}

impl<P: RuntimeProvider> HttpsClientStreamBuilder<P> {
    /// Sets the address to connect from.
    pub fn bind_addr(&mut self, bind_addr: SocketAddr) {
        self.bind_addr = Some(bind_addr);
    }

    /// Set the [`SetHeaders`] trait object used to inject dynamic headers into the DoH request
    pub fn set_headers(&mut self, headers: Arc<dyn SetHeaders>) {
        self.set_headers.replace(headers);
    }

    /// Override the connect timeout (default: 2 seconds).
    ///
    /// This controls both the TCP connect and the HTTP/2 handshake timeouts.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Creates a new [`DnsExchange`] wrapping the [`HttpsClientStream`] from this builder
    pub async fn exchange(
        self,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> Result<DnsExchange<P>, NetError> {
        let mut handle = self.provider.create_handle();
        let stream = self.build(name_server, server_name, path).await?;
        let (exchange, bg) = DnsExchange::from_stream(stream);
        handle.spawn_bg(bg);
        Ok(exchange)
    }

    /// Creates a new HttpsStream to the specified name_server
    ///
    /// # Arguments
    ///
    /// * `name_server` - IP and Port for the remote DNS resolver
    /// * `dns_name` - The DNS name associated with a certificate
    /// * `http_endpoint` - The HTTP endpoint where the remote DNS resolver provides service, typically `/dns-query`
    pub fn build(
        self,
        name_server: SocketAddr,
        server_name: Arc<str>,
        path: Arc<str>,
    ) -> impl Future<Output = Result<HttpsClientStream, NetError>> + Send + 'static {
        connect(
            self.provider.connect_tcp(name_server, self.bind_addr, None),
            self.client_config,
            name_server,
            server_name,
            path,
            self.set_headers,
            self.connect_timeout,
        )
    }
}

/// Creates a new HttpsStream with existing connection
pub fn connect(
    tcp: impl Future<Output = Result<impl DnsTcpStream, io::Error>> + Send + 'static,
    mut client_config: Arc<ClientConfig>,
    name_server: SocketAddr,
    server_name: Arc<str>,
    query_path: Arc<str>,
    set_headers: Option<Arc<dyn SetHeaders>>,
    connect_timeout: Duration,
) -> impl Future<Output = Result<HttpsClientStream, NetError>> + Send + 'static {
    // ensure the ALPN protocol is set correctly
    if client_config.alpn_protocols.is_empty() {
        let mut client_cfg = (*client_config).clone();
        client_cfg.alpn_protocols = vec![ALPN_H2.to_vec()];

        client_config = Arc::new(client_cfg);
    }

    let context = Arc::new(RequestContext {
        version: Version::Http2,
        server_name,
        query_path,
        set_headers,
    });

    async move {
        let tls_server_name = match ServerName::try_from(&*context.server_name) {
            Ok(dns_name) => dns_name.to_owned(),
            Err(err) => {
                return Err(NetError::from(format!(
                    "bad server name {:?}: {err}",
                    context.server_name
                )));
            }
        };

        let (h2, driver) = timeout(connect_timeout, async {
            let tcp = tcp.await?;
            let tls = TlsConnector::from(client_config)
                .connect(tls_server_name, AsyncIoStdAsTokio(tcp))
                .await
                .map_err(NetError::from)?;

            let mut handshake = h2::client::Builder::new();
            handshake.enable_push(false);
            handshake.handshake(tls).await.map_err(NetError::from)
        })
        .await
        .map_err(|_| NetError::Timeout)??;

        debug!("h2 connection established to: {name_server}");
        tokio::spawn(async {
            if let Err(e) = driver.await {
                warn!("h2 connection failed: {e}");
            }
        });

        Ok(HttpsClientStream {
            h2,
            context,
            is_shutdown: false,
        })
    }
}

async fn send(
    h2: SendRequest<Bytes>,
    message: Bytes,
    cx: Arc<RequestContext>,
    method: Method,
) -> Result<DnsResponse, NetError> {
    let mut h2 = h2.ready().await?;
    let mut try_method = method;
    let mut response_stream = loop {
        // build up the http request
        let (request, body) = match try_method {
            Method::GET => (cx.build_get(&message)?, None),
            Method::POST => (cx.build_post(message.remaining())?, Some(message.clone())),
            other => return Err(format!("unsupported method: {other}").into()),
        };
        debug!("request: {:#?}", request);

        // Send the request
        let (response_future, mut send_stream) = h2.send_request(request, body.is_none())?;
        if let Some(body) = body {
            send_stream.send_data(body, true)?;
        }
        let response_stream = response_future.await?;
        debug!("got response: {:#?}", response_stream);
        if response_stream.status() == StatusCode::URI_TOO_LONG && try_method == Method::GET {
            try_method = Method::POST;
            h2 = h2.ready().await?;
        } else {
            break response_stream;
        }
    };
    // get the length of packet
    let content_length = response_stream
        .headers()
        .get(CONTENT_LENGTH)
        .map(|v| v.to_str())
        .transpose()
        .map_err(|e| NetError::from(format!("bad headers received: {e}")))?
        .map(usize::from_str)
        .transpose()
        .map_err(|e| NetError::from(format!("bad headers received: {e}")))?;

    // read the response body
    let response_bytes = fetch_body(response_stream.body_mut(), content_length).await?;

    // Was it a successful request?
    if !response_stream.status().is_success() {
        let error_string = String::from_utf8_lossy(response_bytes.as_ref());

        // TODO: make explicit error type
        return Err(NetError::from(format!(
            "http unsuccessful code: {}, message: {}",
            response_stream.status(),
            error_string
        )));
    } else {
        // verify content type
        {
            // in the case that the ContentType is not specified, we assume it's the standard DNS format
            let content_type = response_stream
                .headers()
                .get(header::CONTENT_TYPE)
                .map(|h| {
                    h.to_str().map_err(|err| {
                        // TODO: make explicit error type
                        NetError::from(format!("ContentType header not a string: {err}"))
                    })
                })
                .unwrap_or(Ok(crate::http::MIME_APPLICATION_DNS))?;

            if content_type != crate::http::MIME_APPLICATION_DNS {
                return Err(NetError::from(format!(
                    "ContentType unsupported (must be '{}'): '{}'",
                    crate::http::MIME_APPLICATION_DNS,
                    content_type
                )));
            }
        }
    };

    // and finally convert the bytes into a DNS message
    DnsResponse::from_buffer(response_bytes.to_vec()).map_err(NetError::from)
}

const ALPN_H2: &[u8] = b"h2";

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use rustls::KeyLogFile;
    use test_support::subscribe;

    use super::*;
    use crate::proto::op::{DnsRequestOptions, Edns, Message, Query};
    use crate::proto::rr::{Name, RData, RecordType};
    use crate::runtime::TokioRuntimeProvider;
    use crate::tls::client_config;
    use crate::xfer::FirstAnswer;

    #[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
    #[tokio::test]
    async fn test_https_google() {
        subscribe();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = client_config_h2();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let provider = TokioRuntimeProvider::new();
        let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
        let connect = https_builder.build(google, Arc::from("dns.google"), Arc::from("/dns-query"));

        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = https
            .send_message(request.clone())
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    #[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
    #[tokio::test]
    async fn test_https_google_with_pure_ip_address_server() {
        subscribe();

        let google = SocketAddr::from(([8, 8, 8, 8], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let mut client_config = client_config_h2();
        client_config.key_log = Arc::new(KeyLogFile::new());

        let provider = TokioRuntimeProvider::new();
        let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
        let connect = https_builder.build(
            google,
            Arc::from(google.ip().to_string()),
            Arc::from("/dns-query"),
        );

        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = https
            .send_message(request.clone())
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    #[cfg(any(feature = "webpki-roots", feature = "rustls-platform-verifier"))]
    #[tokio::test]
    #[ignore = "cloudflare has been unreliable as a public test service"]
    async fn test_https_cloudflare() {
        subscribe();

        let cloudflare = SocketAddr::from(([1, 1, 1, 1], 443));
        let mut request = Message::query();
        let query = Query::new(Name::from_str("www.example.com.").unwrap(), RecordType::A);
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let client_config = client_config_h2();
        let provider = TokioRuntimeProvider::new();
        let https_builder = HttpsClientStream::builder(Arc::new(client_config), provider);
        let connect = https_builder.build(
            cloudflare,
            Arc::from("cloudflare-dns.com"),
            Arc::from("/dns-query"),
        );

        let mut https = connect.await.expect("https connect failed");

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::A(_)))
        );

        //
        // assert that the connection works for a second query
        let mut request = Message::query();
        let query = Query::new(
            Name::from_str("www.example.com.").unwrap(),
            RecordType::AAAA,
        );
        request.add_query(query);
        request.metadata.recursion_desired = true;
        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(1232);
        request.edns = Some(edns);

        let request = DnsRequest::new(request, DnsRequestOptions::default());

        let response = https
            .send_message(request)
            .first_answer()
            .await
            .expect("send_message failed");

        assert!(
            response
                .answers
                .iter()
                .any(|record| matches!(record.data, RData::AAAA(_)))
        );
    }

    fn client_config_h2() -> ClientConfig {
        let mut config = client_config().unwrap();
        config.alpn_protocols = vec![ALPN_H2.to_vec()];
        config
    }
}
