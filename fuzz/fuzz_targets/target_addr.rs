#![no_main]
use libfuzzer_sys::fuzz_target;
use umbra_proto::addr::TargetAddr;

// 不变量：任意目标地址字节不得 panic；长度/域名/尾随字节只返回结构化错误。
// 运行：cargo +nightly fuzz run target_addr
fuzz_target!(|data: &[u8]| {
    let _ = TargetAddr::decode(data);
    let _ = TargetAddr::decode_from(data);
});
