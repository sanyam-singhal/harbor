//! Leptos demo application for Harbor email authentication.

/// Leptos application components and server functions.
pub mod app;

#[cfg(feature = "ssr")]
pub mod auth;

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
/// Hydrates the server-rendered Harbor demo application.
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(app::App);
}
