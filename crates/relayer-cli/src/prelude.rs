//! Application-local prelude.
//!
//! Conveniently import types/functions/macros
//! which are generally useful and should be available in every module with
//! `use crate::prelude::*;

pub use abscissa_core::clap::Parser;
/// Abscissa core prelude
pub use abscissa_core::prelude::*;
pub use abscissa_core::Command;

/// Application state accessors
pub use crate::application::{app_config, app_reader};
