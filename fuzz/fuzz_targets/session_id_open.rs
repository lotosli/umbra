#![no_main]
use libfuzzer_sys::fuzz_target;

// 目标（实现后接入）：umbra_reality::auth::open_session_id(...)
// 不变量：任意 32B session_id + 任意 AAD 都不得 panic；非法输入返回 Err（转发 dest）。
// 运行：cargo +nightly fuzz run session_id_open
fuzz_target!(|data: &[u8]| {
    let _ = data;
});
