package neton.quic.proto

/**
 * Whether quinn's `debug_assert!`s are checked: true in debug binaries (the test executables), false in release ones,
 * like Rust's `cfg(debug_assertions)`.
 */
internal expect val DEBUG_ASSERTIONS: Boolean

/** quinn `debug_assert!`: throws [AssertionError] in debug binaries only. */
internal inline fun debugAssert(condition: Boolean, message: () -> String) {
    if (DEBUG_ASSERTIONS && !condition) throw AssertionError(message())
}
