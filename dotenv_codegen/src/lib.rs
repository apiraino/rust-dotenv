//! This crate provides usage of the `dotenv` crate as a macro.
//! This macro can only work with a .env file, loading an alternate
//! configuration file is not available.

#[macro_use]
extern crate proc_macro_hack;

#[allow(unused_imports)]
#[macro_use]
extern crate dotenv_codegen_impl;
#[doc(hidden)]
pub use dotenv_codegen_impl::*;

proc_macro_expr_decl! {
    dotenv! => expand_dotenv
}
