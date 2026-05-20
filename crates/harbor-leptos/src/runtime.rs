//! Cohesive Harbor auth runtime for Leptos applications.

use harbor_core::{AuthService, CommonPasswordBlocklist, SystemClock, SystemSecretGenerator};

use crate::{AuthApi, AuthFlowConfig, AuthRouteConfig, Harbor};

/// Default clock used by Harbor's web runtime.
pub type DefaultAuthClock = SystemClock;

/// Default secret generator used by Harbor's web runtime.
pub type DefaultAuthSecretGenerator = SystemSecretGenerator;

/// Runtime carrying Harbor config, service, flow config, and route config.
#[derive(Clone)]
pub struct AuthRuntime<
    S,
    M,
    C = DefaultAuthClock,
    G = DefaultAuthSecretGenerator,
    B = CommonPasswordBlocklist,
> {
    harbor: Harbor<S, M>,
    service: AuthService<S, C, G, B>,
    flow_config: AuthFlowConfig,
    route_config: AuthRouteConfig,
}

impl<S, M, C, G, B> core::fmt::Debug for AuthRuntime<S, M, C, G, B>
where
    Harbor<S, M>: core::fmt::Debug,
    AuthFlowConfig: core::fmt::Debug,
    AuthRouteConfig: core::fmt::Debug,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AuthRuntime")
            .field("harbor", &self.harbor)
            .field("service", &"AuthService")
            .field("flow_config", &self.flow_config)
            .field("route_config", &self.route_config)
            .finish()
    }
}

impl<S, M, C, G, B> AuthRuntime<S, M, C, G, B> {
    /// Creates an auth runtime from initialized Harbor primitives.
    #[must_use]
    pub const fn new(
        harbor: Harbor<S, M>,
        service: AuthService<S, C, G, B>,
        flow_config: AuthFlowConfig,
        route_config: AuthRouteConfig,
    ) -> Self {
        Self {
            harbor,
            service,
            flow_config,
            route_config,
        }
    }

    /// Returns the configured Harbor shell.
    #[must_use]
    pub const fn harbor(&self) -> &Harbor<S, M> {
        &self.harbor
    }

    /// Returns the core auth service.
    #[must_use]
    pub const fn service(&self) -> &AuthService<S, C, G, B> {
        &self.service
    }

    /// Returns flow configuration.
    #[must_use]
    pub const fn flow_config(&self) -> &AuthFlowConfig {
        &self.flow_config
    }

    /// Returns route configuration.
    #[must_use]
    pub const fn route_config(&self) -> &AuthRouteConfig {
        &self.route_config
    }

    /// Returns high-level auth API methods.
    #[must_use]
    pub const fn api(&self) -> AuthApi<'_, S, M, C, G, B> {
        AuthApi::new(self)
    }
}
