#![no_main]
use libfuzzer_sys::fuzz_target;

// 目标（实现后接入）：umbra_inner::mux 帧解析
// 不变量：任意字节流不得 panic；长度字段不得导致越界读；未知 cmd 安全丢弃或报错。
// 运行：cargo +nightly fuzz run mux_frame
fuzz_target!(|data: &[u8]| {
    let _ = data;
});
