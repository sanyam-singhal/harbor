use leptos::prelude::{ElementChild, Owner};

use super::{
    Authenticated, EmailCodeForm, ForgotPasswordForm, ResetPasswordForm, SignOutForm, SigninForm,
    SignupForm, Unauthenticated,
};

#[test]
fn form_components_construct_under_owner() {
    let owner = Owner::new();
    owner.with(|| {
        let _signup = SignupForm();
        let _signin = SigninForm();
        let _email = EmailCodeForm();
        let _forgot = ForgotPasswordForm();
        let _reset = ResetPasswordForm();
        let _signout = SignOutForm();
        let _authenticated = leptos::prelude::view! {
            <Authenticated>
                <span>"Account"</span>
            </Authenticated>
        };
        let _unauthenticated = leptos::prelude::view! {
            <Unauthenticated>
                <span>"Signin"</span>
            </Unauthenticated>
        };
    });
}
