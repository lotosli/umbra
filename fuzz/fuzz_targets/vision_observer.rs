#![no_main]

use libfuzzer_sys::fuzz_target;
use umbra_inner::vision_observer::{protected_record_len, Tls13Observer, VisionDirection};

fuzz_target!(|data: &[u8]| {
    let mut observer = Tls13Observer::new();
    // Each packet supplies its direction and bounded chunk length separately.
    let mut remaining = data;
    while remaining.len() >= 2 {
        let direction = if remaining[0] & 1 == 0 {
            VisionDirection::ClientToTarget
        } else {
            VisionDirection::TargetToClient
        };
        let len = (usize::from(remaining[1]) + 1).min(remaining.len() - 2);
        let bytes = &remaining[2..2 + len];
        observer
            .observe(direction, bytes)
            .expect("bounded fuzz input");
        assert!((1..=8192).contains(&observer.read_limit(direction, 8192)));
        if observer.disabled() {
            assert!(!observer.eligible());
            assert!(!observer.is_boundary(direction));
        }
        remaining = &remaining[2 + len..];
    }
    if let Some(header) = data.get(..5).and_then(|h| h.try_into().ok()) {
        if let Ok(len) = protected_record_len(header) {
            assert!((22..=16_645).contains(&len));
        }
    }
});
