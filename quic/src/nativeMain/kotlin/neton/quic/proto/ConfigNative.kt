package neton.quic.proto

/**
 * quinn `EndpointConfig::default()`: a random 64-byte HMAC-SHA256 key for stateless reset tokens (config/mod.rs:148),
 * with the other defaults.
 */
fun EndpointConfig.Companion.default(): EndpointConfig = EndpointConfig(HmacSha256Key.random())
