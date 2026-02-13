//! End-to-end tests that validate full data flow through the tunnel

use std::sync::Arc;
use utun::crypto::{DerivedKeyMaterial, SessionCrypto};
use utun::tunnel::{Frame, FrameCodec, FrameType, Protocol};

#[tokio::test]
async fn test_crypto_bidirectional_frame_roundtrip() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    // Alice uses (enc_key, mac_key)
    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    // Bob uses (mac_key, enc_key) - swapped
    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Alice sends a DATA frame
    let payload = b"Hello from Alice";
    let alice_frame = Frame::new_data(1, 0, payload).unwrap();
    let wire_frame = alice_codec.encode(&alice_frame).unwrap();

    // Bob receives and decodes
    let bob_frame = bob_codec.decode(&wire_frame).unwrap();
    assert_eq!(bob_frame.payload(), payload);
    assert_eq!(bob_frame.frame_type(), FrameType::Data);

    // Bob sends a response
    let response = b"Hello from Bob";
    let bob_frame = Frame::new_data(1, 0, response).unwrap();
    let wire_frame = bob_codec.encode(&bob_frame).unwrap();

    // Alice receives and decodes
    let alice_frame = alice_codec.decode(&wire_frame).unwrap();
    assert_eq!(alice_frame.payload(), response);
    assert_eq!(alice_frame.frame_type(), FrameType::Data);
}

#[tokio::test]
async fn test_multiple_connection_frame_routing() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Simulate 3 concurrent connections
    let conn_ids = [101u32, 102u32, 103u32];
    let payloads = [b"Connection 1", b"Connection 2", b"Connection 3"];

    // Alice sends frames for all 3 connections
    let mut wire_frames = Vec::new();
    for (conn_id, payload) in conn_ids.iter().zip(payloads.iter()) {
        let frame = Frame::new_data(*conn_id, 0, *payload).unwrap();
        wire_frames.push(alice_codec.encode(&frame).unwrap());
    }

    // Bob receives and verifies each frame routes to correct connection
    for (i, wire_frame) in wire_frames.iter().enumerate() {
        let decoded = bob_codec.decode(wire_frame).unwrap();
        assert_eq!(decoded.connection_id(), conn_ids[i]);
        assert_eq!(decoded.payload(), payloads[i]);
    }
}

#[tokio::test]
async fn test_high_volume_nonce_uniqueness_across_connections() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let mut seen_nonces = std::collections::HashSet::new();

    // Send 1000 frames across 10 different connections
    for conn_id in 1..=10 {
        for _ in 0..100 {
            let payload = format!("Data for connection {}", conn_id);
            let frame = Frame::new_data(conn_id, 0, payload.as_bytes()).unwrap();
            let wire_frame = alice_codec.encode(&frame).unwrap();

            // Extract nonce from wire frame (first 12 bytes after length)
            let nonce: [u8; 12] = wire_frame.as_bytes()[0..12].try_into().unwrap();

            assert!(
                seen_nonces.insert(nonce),
                "Duplicate nonce detected for connection {}",
                conn_id
            );
        }
    }

    assert_eq!(seen_nonces.len(), 1000, "Should have 1000 unique nonces");
}

#[tokio::test]
async fn test_connect_ack_frame_routing() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let source_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let source_crypto = Arc::new(SessionCrypto::from_key_material(&source_km));
    let source_codec = FrameCodec::new(source_crypto);

    let dest_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let dest_crypto = Arc::new(SessionCrypto::from_key_material(&dest_km));
    let dest_codec = FrameCodec::new(dest_crypto);

    let conn_id = 42;

    // Destination sends CONNECT_ACK (success)
    let ack_frame = Frame::new_connect_ack(conn_id, true);
    let wire_frame = dest_codec.encode(&ack_frame).unwrap();

    // Source receives and decodes
    let decoded = source_codec.decode(&wire_frame).unwrap();
    assert_eq!(decoded.frame_type(), FrameType::ConnectAck);
    assert_eq!(decoded.connection_id(), conn_id);
    assert!(!decoded.payload().is_empty());
    assert_eq!(decoded.payload()[0], 1); // Success flag

    // Test rejection case
    let reject_frame = Frame::new_connect_ack(conn_id, false);
    let wire_frame = dest_codec.encode(&reject_frame).unwrap();

    let decoded = source_codec.decode(&wire_frame).unwrap();
    assert_eq!(decoded.frame_type(), FrameType::ConnectAck);
    assert_eq!(decoded.connection_id(), conn_id);
    assert!(!decoded.payload().is_empty());
    assert_eq!(decoded.payload()[0], 0); // Rejection flag
}

#[tokio::test]
async fn test_fin_flag_handling() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Create a DATA frame with FIN flag
    let mut frame = Frame::new_data(1, 0, b"Final data").unwrap();
    frame.set_fin();
    assert!(frame.is_fin());

    // Encode and decode
    let wire_frame = alice_codec.encode(&frame).unwrap();
    let decoded = bob_codec.decode(&wire_frame).unwrap();

    // Verify FIN flag is preserved
    assert!(decoded.is_fin());
    assert_eq!(decoded.connection_id(), 1);
    assert_eq!(decoded.payload(), b"Final data");
}

#[tokio::test]
async fn test_concurrent_bidirectional_frames() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Interleaved message exchange
    let mut alice_messages = Vec::new();
    let mut bob_messages = Vec::new();

    for i in 0..50 {
        // Alice sends
        let payload = format!("Alice message {}", i);
        let frame = Frame::new_data(1, 0, payload.as_bytes()).unwrap();
        alice_messages.push((alice_codec.encode(&frame).unwrap(), payload));

        // Bob sends
        let payload = format!("Bob message {}", i);
        let frame = Frame::new_data(1, 0, payload.as_bytes()).unwrap();
        bob_messages.push((bob_codec.encode(&frame).unwrap(), payload));
    }

    // Bob receives Alice's messages
    for (wire_frame, expected) in alice_messages {
        let decoded = bob_codec.decode(&wire_frame).unwrap();
        assert_eq!(std::str::from_utf8(decoded.payload()).unwrap(), expected);
    }

    // Alice receives Bob's messages
    for (wire_frame, expected) in bob_messages {
        let decoded = alice_codec.decode(&wire_frame).unwrap();
        assert_eq!(std::str::from_utf8(decoded.payload()).unwrap(), expected);
    }
}

#[tokio::test]
async fn test_large_payload_fragmentation() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Maximum allowed payload (64KB - 1)
    let large_payload = vec![0xAB; 65535];
    let frame = Frame::new_data(1, 0, &large_payload).unwrap();
    let wire_frame = alice_codec.encode(&frame).unwrap();

    let decoded = bob_codec.decode(&wire_frame).unwrap();
    assert_eq!(decoded.payload(), large_payload.as_slice());
}

#[tokio::test]
async fn test_massive_concurrent_connections() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let source_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let source_crypto = Arc::new(SessionCrypto::from_key_material(&source_km));
    let source_codec = FrameCodec::new(source_crypto);

    let dest_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let dest_crypto = Arc::new(SessionCrypto::from_key_material(&dest_km));
    let dest_codec = FrameCodec::new(dest_crypto);

    let num_connections = 1000;

    // Send frames for 1000 different connections
    for conn_id in 1..=num_connections {
        let payload = format!("Connection {}", conn_id);
        let frame = Frame::new_data(conn_id, 0, payload.as_bytes()).unwrap();
        let wire_frame = source_codec.encode(&frame).unwrap();

        let decoded = dest_codec.decode(&wire_frame).unwrap();
        assert_eq!(decoded.connection_id(), conn_id);
        assert_eq!(
            std::str::from_utf8(decoded.payload()).unwrap(),
            payload.as_str()
        );
    }
}

#[tokio::test]
async fn test_rapid_connection_churn() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let source_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let source_crypto = Arc::new(SessionCrypto::from_key_material(&source_km));
    let source_codec = FrameCodec::new(source_crypto);

    let dest_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let dest_crypto = Arc::new(SessionCrypto::from_key_material(&dest_km));
    let dest_codec = FrameCodec::new(dest_crypto);

    for conn_id in 1..=100 {
        // CONNECT
        let connect = Frame::new_connect(conn_id, 8080, Protocol::Tcp);
        let wire = source_codec.encode(&connect).unwrap();
        let decoded = dest_codec.decode(&wire).unwrap();
        assert_eq!(decoded.frame_type(), FrameType::Connect);

        // CONNECT_ACK
        let ack = Frame::new_connect_ack(conn_id, true);
        let wire = dest_codec.encode(&ack).unwrap();
        let decoded = source_codec.decode(&wire).unwrap();
        assert_eq!(decoded.frame_type(), FrameType::ConnectAck);

        // DATA
        let mut data = Frame::new_data(conn_id, 0, b"Quick data").unwrap();
        let wire = source_codec.encode(&data).unwrap();
        dest_codec.decode(&wire).unwrap();

        // FIN
        data.set_fin();
        let wire = source_codec.encode(&data).unwrap();
        let decoded = dest_codec.decode(&wire).unwrap();
        assert!(decoded.is_fin());
    }
}

#[tokio::test]
async fn test_interleaved_multi_connection_traffic() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Simulate 50 connections sending data in random order
    let connections = 50;
    let messages_per_conn = 20;

    let mut all_frames = Vec::new();

    // Generate all frames
    for conn_id in 1..=connections {
        for msg_num in 0..messages_per_conn {
            let payload = format!("Conn {} Msg {}", conn_id, msg_num);
            let frame = Frame::new_data(conn_id, 0, payload.as_bytes()).unwrap();
            all_frames.push((alice_codec.encode(&frame).unwrap(), conn_id, payload));
        }
    }

    // Verify all frames decode correctly regardless of order
    for (wire_frame, expected_conn, expected_payload) in all_frames {
        let decoded = bob_codec.decode(&wire_frame).unwrap();
        assert_eq!(decoded.connection_id(), expected_conn);
        assert_eq!(
            std::str::from_utf8(decoded.payload()).unwrap(),
            expected_payload
        );
    }
}

#[tokio::test]
async fn test_maximum_payload_boundary_conditions() {
    // Test payloads at exact boundary conditions
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Test various sizes near boundaries
    let test_sizes = vec![
        0,     // Empty
        1,     // Minimum
        16,    // GCM block size
        1024,  // 1KB
        8192,  // 8KB
        32768, // 32KB
        65535, // Maximum
    ];

    for size in test_sizes {
        let payload = vec![0xCC; size];
        let frame = Frame::new_data(1, 0, &payload).unwrap();
        let wire_frame = alice_codec.encode(&frame).unwrap();
        let decoded = bob_codec.decode(&wire_frame).unwrap();
        assert_eq!(decoded.payload().len(), size);
    }
}

#[tokio::test]
async fn test_sequential_nonce_exhaustion() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    let mut seen_nonces = std::collections::HashSet::new();

    // Send 50,000 sequential frames
    for i in 0..50_000 {
        let payload = format!("Message {}", i);
        let frame = Frame::new_data(1, 0, payload.as_bytes()).unwrap();
        let wire_frame = alice_codec.encode(&frame).unwrap();

        // Extract and verify nonce uniqueness
        let nonce: [u8; 12] = wire_frame.as_bytes()[0..12].try_into().unwrap();
        assert!(
            seen_nonces.insert(nonce),
            "Nonce collision at message {}",
            i
        );

        // Verify decodes correctly
        let decoded = bob_codec.decode(&wire_frame).unwrap();
        assert_eq!(
            std::str::from_utf8(decoded.payload()).unwrap(),
            payload.as_str()
        );
    }
}

#[tokio::test]
async fn test_mixed_frame_types_interleaved() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let source_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let source_crypto = Arc::new(SessionCrypto::from_key_material(&source_km));
    let source_codec = FrameCodec::new(source_crypto);

    let dest_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let dest_crypto = Arc::new(SessionCrypto::from_key_material(&dest_km));
    let dest_codec = FrameCodec::new(dest_crypto);

    // Mix of different frame types
    let frames = vec![
        Frame::new_connect(1, 8080, Protocol::Tcp),
        Frame::new_connect_ack(1, true),
        Frame::new_data(1, 0, b"Data 1").unwrap(),
        Frame::new_ping(0),
        Frame::new_pong(0),
        Frame::new_data(2, 0, b"Data 2").unwrap(),
        Frame::new_connect(2, 9090, Protocol::Udp),
        Frame::new_data(1, 0, b"More data").unwrap(),
        Frame::new_connect_ack(2, false),
    ];

    for frame in frames {
        let wire = source_codec.encode(&frame).unwrap();
        let decoded = dest_codec.decode(&wire).unwrap();
        assert_eq!(decoded.frame_type(), frame.frame_type());
        assert_eq!(decoded.connection_id(), frame.connection_id());
    }
}

#[tokio::test]
async fn test_connection_id_collision_resistance() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Use same connection ID but send many frames
    let conn_id = 42;
    for i in 0..1000 {
        let payload = format!("Frame {}", i);
        let frame = Frame::new_data(conn_id, 0, payload.as_bytes()).unwrap();
        let wire = alice_codec.encode(&frame).unwrap();
        let decoded = bob_codec.decode(&wire).unwrap();
        assert_eq!(decoded.connection_id(), conn_id);
    }
}

#[tokio::test]
async fn test_concurrent_encode_decode_safety() {
    use std::sync::Arc;
    use tokio::task::JoinSet;

    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = Arc::new(FrameCodec::new(alice_crypto));

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = Arc::new(FrameCodec::new(bob_crypto));

    let mut tasks = JoinSet::new();

    // Spawn 100 concurrent encoding tasks
    for i in 0..100 {
        let codec = alice_codec.clone();
        tasks.spawn(async move {
            let payload = format!("Concurrent {}", i);
            let frame = Frame::new_data(i, 0, payload.as_bytes()).unwrap();
            codec.encode(&frame).unwrap()
        });
    }

    // Collect all wire frames
    let mut wire_frames = Vec::new();
    while let Some(result) = tasks.join_next().await {
        wire_frames.push(result.unwrap());
    }

    // Decode all frames concurrently
    let mut decode_tasks = JoinSet::new();
    for wire_frame in wire_frames {
        let codec = bob_codec.clone();
        decode_tasks.spawn(async move { codec.decode(&wire_frame).unwrap() });
    }

    // Verify all decode successfully
    let mut count = 0;
    while let Some(result) = decode_tasks.join_next().await {
        result.unwrap();
        count += 1;
    }
    assert_eq!(count, 100);
}

#[tokio::test]
async fn test_memory_stress_large_frame_burst() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Send 100 maximum-size frames rapidly
    for i in 0..100 {
        let large_payload = vec![(i % 256) as u8; 65535];
        let frame = Frame::new_data(i, 0, &large_payload).unwrap();
        let wire_frame = alice_codec.encode(&frame).unwrap();
        let decoded = bob_codec.decode(&wire_frame).unwrap();
        assert_eq!(decoded.payload().len(), 65535);
    }
}

#[tokio::test]
async fn test_alternating_direction_rapid_fire() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    for i in 0..1000 {
        if i % 2 == 0 {
            // Alice -> Bob
            let frame = Frame::new_data(1, 0, b"Alice data").unwrap();
            let wire = alice_codec.encode(&frame).unwrap();
            bob_codec.decode(&wire).unwrap();
        } else {
            // Bob -> Alice
            let frame = Frame::new_data(1, 0, b"Bob data").unwrap();
            let wire = bob_codec.encode(&frame).unwrap();
            alice_codec.decode(&wire).unwrap();
        }
    }
}

#[tokio::test]
async fn test_protocol_type_variations() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let source_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let source_crypto = Arc::new(SessionCrypto::from_key_material(&source_km));
    let source_codec = FrameCodec::new(source_crypto);

    let dest_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let dest_crypto = Arc::new(SessionCrypto::from_key_material(&dest_km));
    let dest_codec = FrameCodec::new(dest_crypto);

    let protocols = [Protocol::Tcp, Protocol::Udp, Protocol::Tcp, Protocol::Udp];

    for (i, protocol) in protocols.iter().enumerate() {
        let frame = Frame::new_connect(i as u32, 8080, *protocol);
        let wire = source_codec.encode(&frame).unwrap();
        let decoded = dest_codec.decode(&wire).unwrap();
        assert_eq!(decoded.frame_type(), FrameType::Connect);
    }
}

#[tokio::test]
async fn test_zero_length_payload_edge_case() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Zero-length DATA frame
    let frame = Frame::new_data(1, 0, b"").unwrap();
    let wire = alice_codec.encode(&frame).unwrap();
    let decoded = bob_codec.decode(&wire).unwrap();
    assert_eq!(decoded.payload().len(), 0);

    // Zero-length with FIN (common for connection close)
    let mut fin_frame = Frame::new_data(1, 0, b"").unwrap();
    fin_frame.set_fin();
    let wire = alice_codec.encode(&fin_frame).unwrap();
    let decoded = bob_codec.decode(&wire).unwrap();
    assert_eq!(decoded.payload().len(), 0);
    assert!(decoded.is_fin());
}

#[tokio::test]
async fn test_replay_attack_detection_comprehensive() {
    let enc_key = [1u8; 32];
    let mac_key = [2u8; 32];

    let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
    let alice_crypto = Arc::new(SessionCrypto::from_key_material(&alice_km));
    let alice_codec = FrameCodec::new(alice_crypto);

    let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
    let bob_crypto = Arc::new(SessionCrypto::from_key_material(&bob_km));
    let bob_codec = FrameCodec::new(bob_crypto);

    // Send 100 frames and save them
    let mut wire_frames = Vec::new();
    for i in 0..100 {
        let payload = format!("Message {}", i);
        let frame = Frame::new_data(1, 0, payload.as_bytes()).unwrap();
        let wire = alice_codec.encode(&frame).unwrap();
        bob_codec.decode(&wire).unwrap(); // Legitimate decode
        wire_frames.push(wire);
    }

    // Try to replay all frames - should all fail
    for (i, wire_frame) in wire_frames.iter().enumerate() {
        match bob_codec.decode(wire_frame) {
            Err(_) => {
                // Expected - replay should fail
            }
            Ok(_) => panic!("Replay attack succeeded at frame {}!", i),
        }
    }
}
