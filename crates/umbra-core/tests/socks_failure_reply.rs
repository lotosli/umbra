//! Wire-level failure replies for a CONNECT that did not reach its target.

use tokio::io::AsyncReadExt;
use umbra_core::socks::write_failure_reply;

#[tokio::test]
async fn failed_connect_returns_general_failure_with_unspecified_bound_address() {
    let (mut client, mut server) = tokio::io::duplex(16);
    write_failure_reply(&mut server).await.expect("reply sent");
    let mut reply = [0; 10];
    client.read_exact(&mut reply).await.expect("complete reply");
    assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn failed_reply_propagates_a_closed_local_socket() {
    let (client, mut server) = tokio::io::duplex(16);
    drop(client);
    assert!(write_failure_reply(&mut server).await.is_err());
}
