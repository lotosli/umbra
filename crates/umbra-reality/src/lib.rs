//! `umbra-reality` — REALITY authentication and related server identity work.
//!
//! Component B lives in [`auth`] and [`replay`]. Certificate forging and dest
//! prebuild are implemented by later components in this crate.

pub mod auth;
pub mod error;
pub mod prebuild;
pub mod replay;

pub use error::RealityError;
