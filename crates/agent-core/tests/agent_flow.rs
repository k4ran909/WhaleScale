//! End-to-end test of the agent's HTTP flow + state machine against a mock
//! coordinator (a real axum server) — no database required.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use ws_agent_core::{Agent, TunnelBackend};
use ws_proto::stats::LatencySample;
use ws_proto::{
    Endpoint, EndpointKind, EndpointUpdate, EnrollRequest, EnrollResponse, NetworkMap, PeerNode,
    RotateRequest, RotateResponse, SelfNode,
};

/// Mock coordinator state.
#[derive(Default)]
struct Mock {
    version: AtomicU64,
    enroll_expiry: Mutex<Option<chrono::DateTime<chrono::Utc>>>,
    enrolled_key: Mutex<Option<String>>,
    rotated_key: Mutex<Option<String>>,
    reported_endpoints: Mutex<Vec<Endpoint>>,
    latency_samples: Mutex<Vec<u32>>,
}

async fn enroll(State(s): State<Arc<Mock>>, Json(req): Json<EnrollRequest>) -> Json<EnrollResponse> {
    *s.enrolled_key.lock().unwrap() = Some(req.public_key);
    Json(EnrollResponse {
        device_id: uuid::Uuid::nil(),
        tenant_id: uuid::Uuid::nil(),
        overlay_ip: "100.64.0.1/32".parse().unwrap(),
        session_token: "tok".into(),
        key_expires_at: *s.enroll_expiry.lock().unwrap(),
    })
}

async fn netmap(State(s): State<Arc<Mock>>) -> Json<NetworkMap> {
    Json(NetworkMap {
        version: s.version.load(Ordering::SeqCst),
        self_node: SelfNode {
            device_id: uuid::Uuid::nil(),
            overlay_ip: "100.64.0.1/32".parse().unwrap(),
            hostname: "self".into(),
        },
        peers: vec![PeerNode {
            device_id: uuid::Uuid::nil(),
            hostname: "peer".into(),
            public_key: "PEERKEY".into(),
            allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
            endpoints: vec![],
            relay_region: None,
            online: true,
            last_seen: None,
        }],
        relays: vec![],
        dns_suffix: None,
        packet_filter: vec![],
    })
}

async fn rotate(
    State(s): State<Arc<Mock>>,
    Json(req): Json<RotateRequest>,
) -> Json<RotateResponse> {
    *s.rotated_key.lock().unwrap() = Some(req.new_public_key);
    Json(RotateResponse {
        key_expires_at: None, // after rotation, no expiry -> no further rotation
    })
}

async fn report_endpoints(
    State(s): State<Arc<Mock>>,
    Json(update): Json<EndpointUpdate>,
) -> StatusCode {
    *s.reported_endpoints.lock().unwrap() = update.endpoints;
    StatusCode::OK
}

async fn report_stats(State(s): State<Arc<Mock>>, Json(sample): Json<LatencySample>) -> StatusCode {
    s.latency_samples.lock().unwrap().push(sample.rtt_ms);
    StatusCode::OK
}

/// Spawn the mock coordinator; returns its base URL and shared state.
async fn spawn_mock(version: u64, expiry: Option<chrono::DateTime<chrono::Utc>>) -> (String, Arc<Mock>) {
    let state = Arc::new(Mock::default());
    state.version.store(version, Ordering::SeqCst);
    *state.enroll_expiry.lock().unwrap() = expiry;

    let app = Router::new()
        .route("/enroll", post(enroll))
        .route("/netmap", get(netmap))
        .route("/rotate", post(rotate))
        .route("/endpoints", post(report_endpoints))
        .route("/stats", post(report_stats))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

/// Backend that records every applied wg-quick config.
#[derive(Clone, Default)]
struct RecordingBackend {
    configs: Arc<Mutex<Vec<String>>>,
}

impl TunnelBackend for RecordingBackend {
    fn apply(&mut self, quick_config: &str, _sync_config: &str) -> anyhow::Result<()> {
        self.configs.lock().unwrap().push(quick_config.to_string());
        Ok(())
    }
}

#[tokio::test]
async fn enroll_then_sync_applies_map_and_dedupes_versions() {
    let (url, mock) = spawn_mock(1, None).await;
    let backend = RecordingBackend::default();
    let configs = backend.configs.clone();
    let mut agent = Agent::new(url, backend);

    agent.enroll("authkey", "host", "linux").await.unwrap();

    // First sync applies v1.
    assert!(agent.sync().await.unwrap(), "v1 should apply");
    // Same version -> no reapply.
    assert!(!agent.sync().await.unwrap(), "unchanged version should not reapply");
    // Bump the version -> reapply.
    mock.version.store(2, Ordering::SeqCst);
    assert!(agent.sync().await.unwrap(), "v2 should apply");

    let configs = configs.lock().unwrap();
    assert_eq!(configs.len(), 2, "exactly two applies");
    assert!(configs[0].contains("PEERKEY"), "config carries the peer key");
    assert!(configs[0].contains("100.64.0.2/32"), "config carries the peer AllowedIPs");
}

/// Start a minimal loopback STUN responder; returns its address.
async fn spawn_stun() -> std::net::SocketAddr {
    use ws_stun::{encode_binding_response, parse_header, TYPE_BINDING_REQUEST};
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            let Ok((len, src)) = sock.recv_from(&mut buf).await else {
                continue;
            };
            if let Some(h) = parse_header(&buf[..len]) {
                if h.msg_type == TYPE_BINDING_REQUEST {
                    let _ = sock.send_to(&encode_binding_response(h.txid, src), src).await;
                }
            }
        }
    });
    addr
}

#[tokio::test]
async fn discover_reports_endpoints_and_latency() {
    let (url, mock) = spawn_mock(1, None).await;
    let stun = spawn_stun().await;
    let mut agent = Agent::new(url, RecordingBackend::default());

    agent.enroll("authkey", "host", "linux").await.unwrap();
    agent.discover_and_report(stun).await.unwrap();

    // A server-reflexive (STUN) endpoint was reported.
    let endpoints = mock.reported_endpoints.lock().unwrap();
    assert!(
        endpoints.iter().any(|e| matches!(e.kind, EndpointKind::Stun)),
        "expected a STUN-discovered endpoint to be reported"
    );

    // A latency sample (STUN RTT) was reported.
    assert_eq!(
        mock.latency_samples.lock().unwrap().len(),
        1,
        "exactly one latency sample reported"
    );
}

#[tokio::test]
async fn rotates_key_when_expiring_soon() {
    let expiry = chrono::Utc::now() + chrono::Duration::minutes(30);
    let (url, mock) = spawn_mock(1, Some(expiry)).await;
    let mut agent = Agent::new(url, RecordingBackend::default());

    agent.enroll("authkey", "host", "linux").await.unwrap();
    let enrolled = mock.enrolled_key.lock().unwrap().clone().unwrap();

    // Expires within an hour -> rotates.
    assert!(
        agent.maybe_rotate(chrono::Duration::hours(1)).await.unwrap(),
        "should rotate when expiring soon"
    );
    let rotated = mock.rotated_key.lock().unwrap().clone().unwrap();
    assert_ne!(enrolled, rotated, "a fresh key was generated");

    // After rotation the expiry is cleared -> no further rotation.
    assert!(
        !agent.maybe_rotate(chrono::Duration::hours(1)).await.unwrap(),
        "should not rotate again"
    );
}
