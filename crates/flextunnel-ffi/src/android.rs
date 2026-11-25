//! JNI surface for the Android app (`../flextunnel-android`).
//!
//! Kotlin reaches native code only through JNI, so this module exposes the
//! session calls of the C ABI as the `external fun`s of one Kotlin object,
//! `dev.flexaccess.flextunnel.FlextunnelNative` — the symbol names below encode
//! that class, and renaming it on either side breaks the link at load time. It
//! adds nothing of its own: every entry point converts Java strings, calls the
//! same safe Rust the C ABI calls ([`FlextunnelHandle`]'s methods,
//! [`start_session`], …), and converts the result back. The JSON shapes are the
//! ones `ios/flextunnel.h` and the crate docs describe.
//!
//! Failures throw `java.lang.IllegalStateException` carrying the message the C
//! ABI would write to its buffer; the Kotlin side declares them with
//! `@Throws`. Handles cross as `jlong` (the raw `*mut FlextunnelHandle`). As
//! with the C ABI, `stop` must be called exactly once per successful `start`,
//! and never concurrently with another call on the same handle — the app's
//! service serializes them.
//!
//! The app's foreground service owns the session for as long as the user keeps
//! it on, so there is no `close_listeners` here: Android does not freeze the
//! process under a running foreground service the way iOS suspends an app.
//!
//! Never unwinds into the JVM: jni's `with_env` catches a panic and the error
//! policy below turns it into an exception (and the release profile is
//! `panic = "abort"` anyway).

use std::ffi::c_void;
use std::sync::OnceLock;

use jni::errors::ErrorPolicy;
use jni::objects::{JClass, JObject, JString};
use jni::strings::JNIString;
use jni::sys::{jboolean, jlong, jstring};
use jni::{Env, EnvUnowned, jni_str};

use crate::{FlextunnelHandle, fetch_server_routes_inner, start_session, stop_session};

/// The default `log` filter when `RUST_LOG` is unset — the one
/// [`crate::flextunnel_init_logging`] uses.
const DEFAULT_LOG_FILTER: &str = "warn,flextunnel_core=info,flextunnel_ffi=info";

/// Set once `init` has registered the app context; later calls are no-ops
/// (ndk-context panics on a second registration).
static ANDROID_CONTEXT: OnceLock<()> = OnceLock::new();

/// A native method's failure: the message for the Kotlin side, or a JNI error.
#[derive(Debug)]
enum NativeError {
    Failed(String),
    Jni(jni::errors::Error),
}

impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NativeError::Failed(message) => f.write_str(message),
            NativeError::Jni(e) => write!(f, "JNI error: {e}"),
        }
    }
}

impl std::error::Error for NativeError {}

impl From<jni::errors::Error> for NativeError {
    fn from(e: jni::errors::Error) -> Self {
        NativeError::Jni(e)
    }
}

impl From<String> for NativeError {
    fn from(message: String) -> Self {
        NativeError::Failed(message)
    }
}

type NativeResult<T> = Result<T, NativeError>;

/// A `jstring` return value, `null` by default — what a method that threw
/// returns.
struct RawString(jstring);

impl Default for RawString {
    fn default() -> Self {
        RawString(std::ptr::null_mut())
    }
}

/// Throw `IllegalStateException(message)` for any error, and for a panic,
/// then return the type's default (`0`, `false`, `null`).
struct ThrowIllegalState;

impl<T: Default> ErrorPolicy<T, NativeError> for ThrowIllegalState {
    type Captures<'unowned_env_local: 'native_method, 'native_method> = ();

    fn on_error<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _cap: &mut Self::Captures<'unowned_env_local, 'native_method>,
        err: NativeError,
    ) -> jni::errors::Result<T> {
        throw(env, &err.to_string());
        Ok(T::default())
    }

    fn on_panic<'unowned_env_local: 'native_method, 'native_method>(
        env: &mut Env<'unowned_env_local>,
        _cap: &mut Self::Captures<'unowned_env_local, 'native_method>,
        payload: Box<dyn std::any::Any + Send + 'static>,
    ) -> jni::errors::Result<T> {
        let message = payload
            .downcast_ref::<&'static str>()
            .map(|s| (*s).to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_string());
        throw(env, &format!("flextunnel panicked: {message}"));
        Ok(T::default())
    }
}

/// Throw `IllegalStateException(message)`, unless an exception is already
/// pending (that one reaches Kotlin instead).
fn throw(env: &mut Env<'_>, message: &str) {
    if env.exception_check() {
        return;
    }
    if let Err(e) = env.throw_new(
        jni_str!("java/lang/IllegalStateException"),
        JNIString::new(message),
    ) {
        log::error!("cannot throw IllegalStateException({message}): {e}");
    }
}

/// `init(context: Context)`: one-time process setup, from
/// `Application.onCreate` before anything else. Routes `log` output to logcat
/// (tag `flextunnel`; stderr is discarded on Android) and registers the JVM
/// and application context with `ndk-context`, which iroh's dependencies
/// (hickory's system DNS lookup, netwatch's interface enumeration) use to
/// reach `ConnectivityManager` — without it the first connection attempt
/// aborts the process. Idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_init<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    context: JObject<'caller>,
) {
    unowned_env
        .with_env(|env| -> NativeResult<()> {
            let filter =
                std::env::var("RUST_LOG").unwrap_or_else(|_| DEFAULT_LOG_FILTER.to_string());
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Trace)
                    .with_tag("flextunnel")
                    .with_filter(android_logger::FilterBuilder::new().parse(&filter).build()),
            );
            if ANDROID_CONTEXT.get().is_some() {
                return Ok(());
            }
            let vm = env.get_java_vm()?;
            // The global ref must outlive every later JNI call through
            // ndk-context, i.e. the process: leak it on purpose.
            let context = env.new_global_ref(&context)?.into_raw();
            // SAFETY: both pointers are valid for the life of the process (the
            // JVM's by construction, the context's through the leaked global
            // ref), and the OnceLock makes this the only registration.
            unsafe {
                ndk_context::initialize_android_context(
                    vm.get_raw().cast::<c_void>(),
                    context.cast::<c_void>(),
                )
            };
            let _ = ANDROID_CONTEXT.set(());
            Ok(())
        })
        .resolve::<ThrowIllegalState>()
}

/// `generateClientKey(): String` — the
/// `{"created":…,"public_key":…,"secret_key":…}` document.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_generateClientKey<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
) -> jstring {
    unowned_env
        .with_env(|env| -> NativeResult<RawString> {
            let json = crate::generate_client_key_json()?;
            new_string(env, &json)
        })
        .resolve::<ThrowIllegalState>()
        .0
}

/// `clientPublicKey(secret: String): String` — the `ed25519-pub:…` half of a
/// secret key; throws for one that does not parse, which makes this the
/// validator for a pasted key too.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_clientPublicKey<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    secret: JString<'caller>,
) -> jstring {
    unowned_env
        .with_env(|env| -> NativeResult<RawString> {
            let secret = get_string(env, &secret, "secret")?;
            let public = crate::client_public_key_str(&secret)?;
            new_string(env, &public)
        })
        .resolve::<ThrowIllegalState>()
        .0
}

/// `start(configJson: String): Long` — validate the config, bind the SOCKS
/// listener if `socks_port` asks for one, and start serving; returns the
/// handle. Connects nothing: a destination connects on first use. At most one
/// session runs at a time.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_start<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    config_json: JString<'caller>,
) -> jlong {
    unowned_env
        .with_env(|env| -> NativeResult<jlong> {
            let json = get_string(env, &config_json, "configJson")?;
            let (handle, _result_json) = start_session(&json)?;
            Ok(Box::into_raw(Box::new(handle)) as jlong)
        })
        .resolve::<ThrowIllegalState>()
}

/// `stop(handle: Long)` — stop the session, close its endpoints, free the
/// handle. `0` is a no-op; the handle is invalid afterwards.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_stop<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) {
    unowned_env
        .with_env(|_env| -> NativeResult<()> {
            if handle != 0 {
                // SAFETY: the Kotlin side passes back a value `start` returned
                // and never uses it after `stop` (see the module docs).
                stop_session(*unsafe { Box::from_raw(handle as *mut FlextunnelHandle) });
            }
            Ok(())
        })
        .resolve::<ThrowIllegalState>()
}

/// `setForwards(handle: Long, forwardsJson: String)` — replace the whole
/// forward set; throws for invalid input.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_setForwards<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    forwards_json: JString<'caller>,
) {
    unowned_env
        .with_env(|env| -> NativeResult<()> {
            let json = get_string(env, &forwards_json, "forwardsJson")?;
            Ok(handle_ref(handle)?.set_forwards(&json)?)
        })
        .resolve::<ThrowIllegalState>()
}

/// `forwardStatuses(handle: Long): String` — the forwards' state JSON.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_forwardStatuses<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) -> jstring {
    unowned_env
        .with_env(|env| -> NativeResult<RawString> {
            let json = handle_ref(handle)?
                .forward_statuses_json()
                .ok_or_else(|| "forward manager lock failed".to_string())?;
            new_string(env, &json)
        })
        .resolve::<ThrowIllegalState>()
        .0
}

/// `status(handle: Long): String` — every destination's state JSON. Never
/// causes a connection.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_status<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) -> jstring {
    unowned_env
        .with_env(|env| -> NativeResult<RawString> {
            let json = handle_ref(handle)?.status_json();
            new_string(env, &json)
        })
        .resolve::<ThrowIllegalState>()
        .0
}

/// `connPath(handle: Long, name: String): String` — the named destination's
/// path snapshot. Blocks on the custom relays' health checks: call it off the
/// main thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_connPath<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    name: JString<'caller>,
) -> jstring {
    unowned_env
        .with_env(|env| -> NativeResult<RawString> {
            let name = get_string(env, &name, "name")?;
            let json = handle_ref(handle)?.conn_path_json(&name);
            new_string(env, &json)
        })
        .resolve::<ThrowIllegalState>()
        .0
}

/// `isServing(handle: Long): Boolean` — `false` once the client has ended (a
/// local listener lost for good).
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_isServing<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
) -> jboolean {
    unowned_env
        .with_env(|_env| -> NativeResult<jboolean> { Ok(handle_ref(handle)?.is_serving()) })
        .resolve::<ThrowIllegalState>()
}

/// `setBackground(handle: Long, background: Boolean)` — the heartbeat slows
/// from 10s to 60s while the app's UI is not visible.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_setBackground<'caller>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    background: jboolean,
) {
    unowned_env
        .with_env(|_env| -> NativeResult<()> {
            handle_ref(handle)?.client.set_background(background);
            Ok(())
        })
        .resolve::<ThrowIllegalState>()
}

/// `setNetworkAvailable(handle: Long, available: Boolean)` — from
/// `ConnectivityManager`'s default-network callback: while unavailable nothing
/// is dialed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_setNetworkAvailable<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    handle: jlong,
    available: jboolean,
) {
    unowned_env
        .with_env(|_env| -> NativeResult<()> {
            handle_ref(handle)?.client.set_network_available(available);
            Ok(())
        })
        .resolve::<ThrowIllegalState>()
}

/// `fetchServerRoutes(requestJson: String): String` — ask a server what it
/// routes, outside any session. Blocks until it answers (seconds; about a
/// minute against one that never does): call it off the main thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_flextunnel_FlextunnelNative_fetchServerRoutes<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    request_json: JString<'caller>,
) -> jstring {
    unowned_env
        .with_env(|env| -> NativeResult<RawString> {
            let json = get_string(env, &request_json, "requestJson")?;
            let routes = fetch_server_routes_inner(&json)?;
            new_string(env, &routes)
        })
        .resolve::<ThrowIllegalState>()
        .0
}

/// Borrow the handle behind a `jlong`; `0` is an error.
fn handle_ref<'a>(handle: jlong) -> NativeResult<&'a FlextunnelHandle> {
    if handle == 0 {
        return Err(NativeError::Failed("null handle".to_string()));
    }
    // SAFETY: a nonzero value is a live handle from `start` (see the module
    // docs for the contract).
    Ok(unsafe { &*(handle as *const FlextunnelHandle) })
}

/// Copy a Java string argument out; null is an error naming `what`.
fn get_string(env: &Env<'_>, s: &JString<'_>, what: &str) -> NativeResult<String> {
    if s.is_null() {
        return Err(NativeError::Failed(format!("{what} is null")));
    }
    Ok(s.try_to_string(env)?)
}

/// A new Java string for a return value.
fn new_string(env: &mut Env<'_>, s: &str) -> NativeResult<RawString> {
    Ok(RawString(JString::from_str(env, s)?.into_raw()))
}
