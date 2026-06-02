//! Integration test: two agent relay clients exchange a packet through a real
//! (loopback) relay server.

use ws_agent_core::relay_client::RelayClient;

#[tokio::test]
async fn relays_packet_between_two_clients() {
    // Start the relay server on an ephemeral loopback port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = ws_relay::router(ws_relay::RelayState::default());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let url = format!("ws://{addr}/relay");

    // Alice and Bob connect and register their public keys.
    let mut alice = RelayClient::connect(&url, "ALICE_PUBKEY", "tok")
        .await
        .unwrap();
    let mut bob = RelayClient::connect(&url, "BOB_PUBKEY", "tok")
        .await
        .unwrap();

    // Give the server a moment to register both before forwarding.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Alice sends an (opaque) encrypted packet addressed to Bob.
    let packet = b"ciphertext-wireguard-payload";
    alice.send("BOB_PUBKEY", packet).await.unwrap();

    // Bob receives it, tagged with Alice's key.
    let (src, payload) = tokio::time::timeout(std::time::Duration::from_secs(2), bob.recv())
        .await
        .expect("recv did not time out")
        .expect("recv ok")
        .expect("a frame arrived");

    assert_eq!(src, "ALICE_PUBKEY");
    assert_eq!(payload, packet);
}
