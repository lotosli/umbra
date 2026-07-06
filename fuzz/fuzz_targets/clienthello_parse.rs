#![no_main]
use libfuzzer_sys::fuzz_target;

// 目标（实现后接入）：umbra_tls::parse::parse_client_hello(data)
// 不变量：任意字节输入都不得 panic / 越界；解析结果要么 Ok(ParsedHello) 要么 Err。
// 运行：cargo +nightly fuzz run clienthello_parse
fuzz_target!(|data: &[u8]| {
    let _ = data;
});
