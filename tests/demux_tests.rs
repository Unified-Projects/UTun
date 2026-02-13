//! Tests for frame demultiplexing on the source side
//!
//! These tests verify that the connection registry and frame routing
//! work correctly to multiplex/demultiplex frames to the correct connections.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use utun::tunnel::{Frame, FrameType, Protocol};

#[tokio::test]
async fn test_basic_frame_routing() {
    // Simulated registry
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Create 3 connections
    let (tx1, mut rx1) = mpsc::channel(100);
    let (tx2, mut rx2) = mpsc::channel(100);
    let (tx3, mut rx3) = mpsc::channel(100);

    {
        let mut reg = registry.write().await;
        reg.insert(1, tx1);
        reg.insert(2, tx2);
        reg.insert(3, tx3);
    }

    // Route frames to each connection
    let frame1 = Frame::new_data(1, 0, b"Data for conn 1").unwrap();
    let frame2 = Frame::new_data(2, 0, b"Data for conn 2").unwrap();
    let frame3 = Frame::new_data(3, 0, b"Data for conn 3").unwrap();

    {
        let reg = registry.read().await;
        reg.get(&1).unwrap().send(frame1.clone()).await.unwrap();
        reg.get(&2).unwrap().send(frame2.clone()).await.unwrap();
        reg.get(&3).unwrap().send(frame3.clone()).await.unwrap();
    }

    // Verify each connection received the correct frame
    let received1 = rx1.recv().await.unwrap();
    assert_eq!(received1.connection_id(), 1);
    assert_eq!(received1.payload(), b"Data for conn 1");

    let received2 = rx2.recv().await.unwrap();
    assert_eq!(received2.connection_id(), 2);
    assert_eq!(received2.payload(), b"Data for conn 2");

    let received3 = rx3.recv().await.unwrap();
    assert_eq!(received3.connection_id(), 3);
    assert_eq!(received3.payload(), b"Data for conn 3");
}

#[tokio::test]
async fn test_unknown_connection_handling() {
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx1, _rx1) = mpsc::channel(100);

    {
        let mut reg = registry.write().await;
        reg.insert(1, tx1);
    }

    // Try to route frame to unknown connection
    let _frame_unknown = Frame::new_data(999, 0, b"Unknown conn").unwrap();

    let reg = registry.read().await;
    assert!(reg.get(&999).is_none(), "Connection 999 should not exist");
}

#[tokio::test]
async fn test_concurrent_connection_registration() {
    use tokio::task::JoinSet;

    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let mut tasks = JoinSet::new();

    // Register 100 connections concurrently
    for conn_id in 1..=100 {
        let reg_clone = registry.clone();
        tasks.spawn(async move {
            let (tx, _rx) = mpsc::channel(100);
            let mut reg = reg_clone.write().await;
            reg.insert(conn_id, tx);
        });
    }

    // Wait for all registrations
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }

    // Verify all 100 connections are registered
    let reg = registry.read().await;
    assert_eq!(reg.len(), 100);
    for conn_id in 1..=100 {
        assert!(reg.contains_key(&conn_id));
    }
}

#[tokio::test]
async fn test_connection_unregistration() {
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx1, _rx1) = mpsc::channel(100);
    let (tx2, _rx2) = mpsc::channel(100);

    {
        let mut reg = registry.write().await;
        reg.insert(1, tx1);
        reg.insert(2, tx2);
    }

    // Verify both registered
    {
        let reg = registry.read().await;
        assert_eq!(reg.len(), 2);
    }

    // Unregister connection 1
    {
        let mut reg = registry.write().await;
        reg.remove(&1);
    }

    // Verify only connection 2 remains
    {
        let reg = registry.read().await;
        assert_eq!(reg.len(), 1);
        assert!(reg.contains_key(&2));
        assert!(!reg.contains_key(&1));
    }
}

#[tokio::test]
async fn test_channel_closed_detection() {
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx1, rx1) = mpsc::channel(100);

    {
        let mut reg = registry.write().await;
        reg.insert(1, tx1);
    }

    // Drop receiver to simulate connection closure
    drop(rx1);

    // Try to send frame - should fail
    let frame = Frame::new_data(1, 0, b"Test").unwrap();

    let reg = registry.read().await;
    let result = reg.get(&1).unwrap().send(frame).await;
    assert!(result.is_err(), "Send should fail when channel is closed");
}

#[tokio::test]
async fn test_high_volume_routing() {
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let num_connections = 10;
    let frames_per_conn = 100;

    // Create receivers for collecting frames
    let mut receivers = Vec::new();

    // Register connections
    {
        let mut reg = registry.write().await;
        for conn_id in 1..=num_connections {
            let (tx, rx) = mpsc::channel(frames_per_conn);
            reg.insert(conn_id, tx);
            receivers.push((conn_id, rx));
        }
    }

    // Send frames to each connection
    for conn_id in 1..=num_connections {
        let reg = registry.read().await;
        let tx = reg.get(&conn_id).unwrap();

        for i in 0..frames_per_conn {
            let payload = format!("Conn {} Frame {}", conn_id, i);
            let frame = Frame::new_data(conn_id, 0, payload.as_bytes()).unwrap();
            tx.send(frame).await.unwrap();
        }
    }

    // Verify each connection received all frames
    for (conn_id, mut rx) in receivers {
        for i in 0..frames_per_conn {
            let frame = rx.recv().await.unwrap();
            assert_eq!(frame.connection_id(), conn_id);
            let expected = format!("Conn {} Frame {}", conn_id, i);
            assert_eq!(frame.payload(), expected.as_bytes());
        }
    }
}

#[tokio::test]
async fn test_interleaved_routing() {
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx1, mut rx1) = mpsc::channel(100);
    let (tx2, mut rx2) = mpsc::channel(100);
    let (tx3, mut rx3) = mpsc::channel(100);

    {
        let mut reg = registry.write().await;
        reg.insert(1, tx1);
        reg.insert(2, tx2);
        reg.insert(3, tx3);
    }

    // Send frames in interleaved order: 1, 2, 3, 1, 2, 3, 1, 2, 3
    let send_order = vec![1, 2, 3, 1, 2, 3, 1, 2, 3];

    for (i, conn_id) in send_order.iter().enumerate() {
        let payload = format!("Frame {}", i);
        let frame = Frame::new_data(*conn_id, 0, payload.as_bytes()).unwrap();

        let reg = registry.read().await;
        reg.get(conn_id).unwrap().send(frame).await.unwrap();
    }

    // Verify each connection received exactly 3 frames
    for _ in 0..3 {
        let f1 = rx1.recv().await.unwrap();
        assert_eq!(f1.connection_id(), 1);

        let f2 = rx2.recv().await.unwrap();
        assert_eq!(f2.connection_id(), 2);

        let f3 = rx3.recv().await.unwrap();
        assert_eq!(f3.connection_id(), 3);
    }
}

#[tokio::test]
async fn test_connect_ack_routing() {
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx1, mut rx1) = mpsc::channel(100);

    {
        let mut reg = registry.write().await;
        reg.insert(1, tx1);
    }

    // Send CONNECT_ACK frame
    let ack = Frame::new_connect_ack(1, true);

    {
        let reg = registry.read().await;
        reg.get(&1).unwrap().send(ack).await.unwrap();
    }

    // Verify CONNECT_ACK received
    let received = rx1.recv().await.unwrap();
    assert_eq!(received.frame_type(), FrameType::ConnectAck);
    assert_eq!(received.connection_id(), 1);
}

#[tokio::test]
async fn test_fin_flag_routing() {
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx1, mut rx1) = mpsc::channel(100);

    {
        let mut reg = registry.write().await;
        reg.insert(1, tx1);
    }

    // Send DATA frame with FIN flag
    let mut frame = Frame::new_data(1, 0, b"Final data").unwrap();
    frame.set_fin();

    {
        let reg = registry.read().await;
        reg.get(&1).unwrap().send(frame).await.unwrap();
    }

    // Verify FIN frame received
    let received = rx1.recv().await.unwrap();
    assert!(received.is_fin());
    assert_eq!(received.payload(), b"Final data");
}

#[tokio::test]
async fn test_registry_race_conditions() {
    // Test for race conditions in concurrent read/write access
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    use tokio::task::JoinSet;
    let mut tasks = JoinSet::new();

    // Concurrent registration and routing
    for i in 0..50 {
        let reg_clone = registry.clone();
        tasks.spawn(async move {
            let (tx, mut rx) = mpsc::channel(10);

            // Register
            {
                let mut reg = reg_clone.write().await;
                reg.insert(i, tx);
            }

            // Route frame
            {
                let reg = reg_clone.read().await;
                if let Some(tx) = reg.get(&i) {
                    let frame = Frame::new_data(i, 0, b"Test").unwrap();
                    let _ = tx.send(frame).await;
                }
            }

            // Receive
            rx.recv().await
        });
    }

    // All should complete without deadlock
    let mut count = 0;
    while let Some(result) = tasks.join_next().await {
        assert!(result.unwrap().is_some());
        count += 1;
    }
    assert_eq!(count, 50);
}

#[tokio::test]
async fn test_frame_type_filtering() {
    // Verify that different frame types route correctly
    let registry: Arc<RwLock<HashMap<u32, mpsc::Sender<Frame>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let (tx1, mut rx1) = mpsc::channel(100);

    {
        let mut reg = registry.write().await;
        reg.insert(1, tx1);
    }

    // Send different frame types
    let frames = vec![
        Frame::new_data(1, 0, b"Data").unwrap(),
        Frame::new_connect_ack(1, true),
        Frame::new_connect(1, 8080, Protocol::Tcp),
    ];

    {
        let reg = registry.read().await;
        let tx = reg.get(&1).unwrap();
        for frame in frames {
            tx.send(frame).await.unwrap();
        }
    }

    // Verify all frame types received
    let f1 = rx1.recv().await.unwrap();
    assert_eq!(f1.frame_type(), FrameType::Data);

    let f2 = rx1.recv().await.unwrap();
    assert_eq!(f2.frame_type(), FrameType::ConnectAck);

    let f3 = rx1.recv().await.unwrap();
    assert_eq!(f3.frame_type(), FrameType::Connect);
}
