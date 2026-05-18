//! Server-renderable Leptos auth components.

use leptos::prelude::{CustomAttribute, ElementChild};

/// Email/password signup form.
#[leptos::prelude::component]
pub fn SignupForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/signup" data-harbor-form="signup">
            <label for="harbor-signup-email">"Email"</label>
            <input id="harbor-signup-email" name="email" type="email" autocomplete="email" required />
            <label for="harbor-signup-password">"Password"</label>
            <input id="harbor-signup-password" name="password" type="password" autocomplete="new-password" required />
            <button type="submit">"Sign up"</button>
        </form>
    }
}

/// Email/password signin form.
#[leptos::prelude::component]
pub fn SigninForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/signin" data-harbor-form="signin">
            <label for="harbor-signin-email">"Email"</label>
            <input id="harbor-signin-email" name="email" type="email" autocomplete="email" required />
            <label for="harbor-signin-password">"Password"</label>
            <input id="harbor-signin-password" name="password" type="password" autocomplete="current-password" required />
            <button type="submit">"Sign in"</button>
        </form>
    }
}

/// Email OTP/link request form.
#[leptos::prelude::component]
pub fn EmailCodeForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/email" data-harbor-form="email-code">
            <label for="harbor-email-code-email">"Email"</label>
            <input id="harbor-email-code-email" name="email" type="email" autocomplete="email" required />
            <button type="submit">"Email me a sign-in link"</button>
        </form>
    }
}

/// Forgot-password request form.
#[leptos::prelude::component]
pub fn ForgotPasswordForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/forgot-password" data-harbor-form="forgot-password">
            <label for="harbor-forgot-email">"Email"</label>
            <input id="harbor-forgot-email" name="email" type="email" autocomplete="email" required />
            <button type="submit">"Reset password"</button>
        </form>
    }
}

/// Password reset form.
#[leptos::prelude::component]
pub fn ResetPasswordForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/reset-password" data-harbor-form="reset-password">
            <input name="challenge_id" type="hidden" />
            <input name="token" type="hidden" />
            <label for="harbor-reset-password">"New password"</label>
            <input id="harbor-reset-password" name="password" type="password" autocomplete="new-password" required />
            <button type="submit">"Save password"</button>
        </form>
    }
}

/// Signout form.
#[leptos::prelude::component]
pub fn SignOutForm() -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <form method="post" action="/api/auth/signout" data-harbor-form="signout">
            <button type="submit">"Sign out"</button>
        </form>
    }
}

/// Shows children only on authenticated pages.
///
/// This component is intentionally structural in v0.1. Applications should
/// render it only after loading a server-side session view.
#[leptos::prelude::component]
pub fn Authenticated(children: leptos::prelude::Children) -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <div data-harbor-auth-state="authenticated">{children()}</div>
    }
}

/// Shows children only on unauthenticated pages.
///
/// This component is intentionally structural in v0.1. Applications should
/// render it only after loading a server-side session view.
#[leptos::prelude::component]
pub fn Unauthenticated(children: leptos::prelude::Children) -> impl leptos::prelude::IntoView {
    leptos::prelude::view! {
        <div data-harbor-auth-state="unauthenticated">{children()}</div>
    }
}

#[cfg(test)]
mod tests;
