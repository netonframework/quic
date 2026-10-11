package neton.quic.proto

/**
 * quinn `EndpointConfig::default()`: a random 64-byte HMAC-SHA256 key for stateless reset tokens (config/mod.rs:148),
 * with the other defaults.
 */
fun EndpointConfig.Companion.default(): EndpointConfig = EndpointConfig(HmacSha256Key.random())

/**
 * quinn `ServerConfig::with_crypto` (config/mod.rs:396): a server configuration for [crypto] with a handshake token key
 * derived by HKDF-SHA256 from 64 random bytes.
 */
fun ServerConfig.Companion.withCrypto(crypto: CryptoServerConfig): ServerConfig =
    ServerConfig(crypto, HkdfSha256TokenKey.random())
