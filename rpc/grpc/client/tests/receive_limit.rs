use futures::Stream;
use kaspa_grpc_client::{GrpcClient, error::Error};
use kaspa_grpc_core::{
    RPC_MAX_MESSAGE_SIZE,
    protowire::{
        GetInfoResponseMessage, KaspadRequest, KaspadResponse,
        kaspad_response::Payload,
        rpc_server::{Rpc, RpcServer},
    },
};
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle, time::timeout};
use tonic::{Request, Response, Status, codec::CompressionEncoding, transport::Server};

#[derive(Clone)]
struct ResponseServer {
    large_version_bytes: usize,
    connections: Arc<AtomicUsize>,
    close_first_after_handshake: bool,
}

#[tonic::async_trait]
impl Rpc for ResponseServer {
    type MessageStreamStream = Pin<Box<dyn Stream<Item = Result<KaspadResponse, Status>> + Send>>;

    async fn message_stream(
        &self,
        request: Request<tonic::Streaming<KaspadRequest>>,
    ) -> Result<Response<Self::MessageStreamStream>, Status> {
        let mut requests = request.into_inner();
        let large_version_bytes = self.large_version_bytes;
        let connection_number = self.connections.fetch_add(1, Ordering::SeqCst);
        let close_after_handshake = self.close_first_after_handshake && connection_number == 0;
        let responses = async_stream::try_stream! {
            let mut first = true;
            while let Some(request) = requests.message().await? {
                let server_version = if first {
                    first = false;
                    "small".to_string()
                } else {
                    "a".repeat(large_version_bytes)
                };
                yield KaspadResponse {
                    id: request.id,
                    payload: Some(Payload::GetInfoResponse(GetInfoResponseMessage {
                        server_version,
                        has_message_id: true,
                        ..Default::default()
                    })),
                };
                if close_after_handshake {
                    break;
                }
            }
        };
        Ok(Response::new(Box::pin(responses)))
    }
}

async fn serve(
    compressed: bool,
    close_first_after_handshake: bool,
) -> (String, Arc<AtomicUsize>, oneshot::Sender<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("grpc://{}", listener.local_addr().unwrap());
    let incoming = async_stream::stream! {
        loop {
            yield listener.accept().await.map(|(stream, _)| stream);
        }
    };
    let connections = Arc::new(AtomicUsize::new(0));
    let mut service = RpcServer::new(ResponseServer {
        large_version_bytes: 8 * 1024,
        connections: connections.clone(),
        close_first_after_handshake,
    })
    .accept_compressed(CompressionEncoding::Gzip);
    if compressed {
        service = service.send_compressed(CompressionEncoding::Gzip);
    }
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    (url, connections, stop, task)
}

async fn connect_with_limit(url: String, limit: Option<usize>) -> kaspa_grpc_client::error::Result<GrpcClient> {
    GrpcClient::connect_with_args_and_receive_limit(
        NotificationMode::Direct,
        url,
        None,
        false,
        None,
        false,
        Some(1_000),
        Default::default(),
        limit,
    )
    .await
}

#[tokio::test]
async fn invalid_receive_limits_fail_before_dialing() {
    for limit in [0, RPC_MAX_MESSAGE_SIZE + 1] {
        let result = timeout(Duration::from_secs(2), connect_with_limit("grpc://127.0.0.1:9".to_string(), Some(limit))).await.unwrap();
        assert!(matches!(result, Err(Error::String(message)) if message.contains("receive limit")));
    }
}

#[tokio::test]
async fn explicit_limit_rejects_oversized_plain_and_gzip_responses() {
    for compressed in [false, true] {
        let (url, _, stop, server) = serve(compressed, false).await;
        let legacy = timeout(Duration::from_secs(5), GrpcClient::connect(url.clone())).await.unwrap().unwrap();
        let legacy_response = timeout(Duration::from_secs(5), legacy.get_info()).await.unwrap().unwrap();
        assert_eq!(legacy_response.server_version.len(), 8 * 1024);
        legacy.disconnect().await.unwrap();

        let legacy_args = timeout(
            Duration::from_secs(5),
            GrpcClient::connect_with_args(
                NotificationMode::Direct,
                url.clone(),
                None,
                false,
                None,
                false,
                Some(1_000),
                Default::default(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(timeout(Duration::from_secs(5), legacy_args.get_info()).await.unwrap().unwrap().server_version.len(), 8 * 1024);
        legacy_args.disconnect().await.unwrap();

        let explicit_default =
            timeout(Duration::from_secs(5), connect_with_limit(url.clone(), Some(RPC_MAX_MESSAGE_SIZE))).await.unwrap().unwrap();
        assert_eq!(
            timeout(Duration::from_secs(5), explicit_default.get_info()).await.unwrap().unwrap().server_version.len(),
            8 * 1024
        );
        explicit_default.disconnect().await.unwrap();

        let limited = timeout(Duration::from_secs(5), connect_with_limit(url, Some(4 * 1024))).await.unwrap().unwrap();
        let request = tokio::spawn({
            let client = limited.clone();
            async move { client.get_info().await }
        });
        timeout(Duration::from_secs(5), async {
            while limited.is_connected() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        if request.is_finished() {
            assert!(request.await.unwrap().is_err());
        } else {
            request.abort();
        }
        limited.disconnect().await.unwrap();
        stop.send(()).unwrap();
        timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn receive_limit_is_retained_after_automatic_reconnect() {
    let (url, connections, stop, server) = serve(false, true).await;
    let client = timeout(
        Duration::from_secs(5),
        GrpcClient::connect_with_args_and_receive_limit(
            NotificationMode::Direct,
            url,
            None,
            true,
            None,
            false,
            Some(1_000),
            Default::default(),
            Some(4 * 1024),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    timeout(Duration::from_secs(8), async {
        while connections.load(Ordering::SeqCst) < 2 || !client.is_connected() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let request = tokio::spawn({
        let client = client.clone();
        async move { client.get_info().await }
    });
    timeout(Duration::from_secs(5), async {
        while client.is_connected() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    if request.is_finished() {
        assert!(request.await.unwrap().is_err());
    } else {
        request.abort();
    }
    client.disconnect().await.unwrap();
    stop.send(()).unwrap();
    timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
}
