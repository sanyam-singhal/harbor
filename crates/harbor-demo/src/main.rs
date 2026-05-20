//! SSR entrypoint for the Harbor Leptos demo.

#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use axum::Router;
    use axum::routing::get;
    use harbor_demo::app::{App, shell};
    use harbor_demo::auth::{DemoState, provide_demo_state};
    use leptos::config::get_configuration;
    use leptos_axum::{LeptosRoutes, file_and_error_handler_with_context, generate_route_list};

    let configuration = get_configuration(None)
        .or_else(|_error| get_configuration(Some("crates/harbor-demo/Cargo.toml")))?;
    let leptos_options = configuration.leptos_options;
    let addr = leptos_options.site_addr;
    let state = DemoState::from_env(leptos_options.clone()).await?;
    let routes = generate_route_list(App);
    let context = {
        let state = state.clone();
        move || provide_demo_state(state.clone())
    };
    let fallback_context = {
        let state = state.clone();
        move || provide_demo_state(state.clone())
    };
    let auth_router = state.auth_router();
    let app = Router::<DemoState>::new()
        .route("/healthz", get(|| async { "ok" }))
        .leptos_routes_with_context(&state, routes, context, {
            let leptos_options = leptos_options.clone();
            move || shell(leptos_options.clone())
        })
        .fallback(file_and_error_handler_with_context::<DemoState, _>(
            fallback_context,
            shell,
        ))
        .with_state(state)
        .merge(auth_router);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

#[cfg(not(feature = "ssr"))]
/// Client builds hydrate through `lib.rs`.
pub fn main() {}
