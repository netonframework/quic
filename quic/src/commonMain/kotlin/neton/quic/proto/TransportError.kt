package neton.quic.proto

import neton.io.bytes.Buffer

/**
 * Transport-level error code (quinn `transport_error::Code`, transport_error.rs:46; RFC 9000 §20.1).
 */
value class TransportErrorCode(val value: Long) {

    fun encode(buf: Buffer) = buf.writeVar(value)

    /** Human-readable description (quinn's `Display`). */
    val description: String
        get() = DESCRIPTIONS[value]
            ?: if (value in 0x100 until 0x200) "the cryptographic handshake failed: error ${value and 0xFF}" else "unknown error"

    /** quinn's `Debug`: the constant's name, `Code::crypto(xx)` or `Code(x)`. */
    override fun toString(): String = NAMES[value]
        ?: if (value in 0x100 until 0x200) "Code::crypto(${(value and 0xFF).toString(16).padStart(2, '0')})" else "Code(${value.toString(16)})"

    companion object {
        /** Create a QUIC error code from a TLS alert code. */
        fun crypto(code: Int): TransportErrorCode = TransportErrorCode(0x100L or (code.toLong() and 0xFF))

        fun decode(r: Reader): TransportErrorCode = TransportErrorCode(r.getVar())

        val NO_ERROR = TransportErrorCode(0x0)
        val INTERNAL_ERROR = TransportErrorCode(0x1)
        val CONNECTION_REFUSED = TransportErrorCode(0x2)
        val FLOW_CONTROL_ERROR = TransportErrorCode(0x3)
        val STREAM_LIMIT_ERROR = TransportErrorCode(0x4)
        val STREAM_STATE_ERROR = TransportErrorCode(0x5)
        val FINAL_SIZE_ERROR = TransportErrorCode(0x6)
        val FRAME_ENCODING_ERROR = TransportErrorCode(0x7)
        val TRANSPORT_PARAMETER_ERROR = TransportErrorCode(0x8)
        val CONNECTION_ID_LIMIT_ERROR = TransportErrorCode(0x9)
        val PROTOCOL_VIOLATION = TransportErrorCode(0xA)
        val INVALID_TOKEN = TransportErrorCode(0xB)
        val APPLICATION_ERROR = TransportErrorCode(0xC)
        val CRYPTO_BUFFER_EXCEEDED = TransportErrorCode(0xD)
        val KEY_UPDATE_ERROR = TransportErrorCode(0xE)
        val AEAD_LIMIT_REACHED = TransportErrorCode(0xF)
        val NO_VIABLE_PATH = TransportErrorCode(0x10)

        private val NAMES: Map<Long, String> = mapOf(
            0x0L to "NO_ERROR", 0x1L to "INTERNAL_ERROR", 0x2L to "CONNECTION_REFUSED", 0x3L to "FLOW_CONTROL_ERROR",
            0x4L to "STREAM_LIMIT_ERROR", 0x5L to "STREAM_STATE_ERROR", 0x6L to "FINAL_SIZE_ERROR",
            0x7L to "FRAME_ENCODING_ERROR", 0x8L to "TRANSPORT_PARAMETER_ERROR", 0x9L to "CONNECTION_ID_LIMIT_ERROR",
            0xAL to "PROTOCOL_VIOLATION", 0xBL to "INVALID_TOKEN", 0xCL to "APPLICATION_ERROR",
            0xDL to "CRYPTO_BUFFER_EXCEEDED", 0xEL to "KEY_UPDATE_ERROR", 0xFL to "AEAD_LIMIT_REACHED",
            0x10L to "NO_VIABLE_PATH",
        )

        private val DESCRIPTIONS: Map<Long, String> = mapOf(
            0x0L to "the connection is being closed abruptly in the absence of any error",
            0x1L to "the endpoint encountered an internal error and cannot continue with the connection",
            0x2L to "the server refused to accept a new connection",
            0x3L to "received more data than permitted in advertised data limits",
            0x4L to "received a frame for a stream identifier that exceeded advertised the stream limit for the corresponding stream type",
            0x5L to "received a frame for a stream that was not in a state that permitted that frame",
            0x6L to "received a STREAM frame or a RESET_STREAM frame containing a different final size to the one already established",
            0x7L to "received a frame that was badly formatted",
            0x8L to "received transport parameters that were badly formatted, included an invalid value, was absent even though it is mandatory, was present though it is forbidden, or is otherwise in error",
            0x9L to "the number of connection IDs provided by the peer exceeds the advertised active_connection_id_limit",
            0xAL to "detected an error with protocol compliance that was not covered by more specific error codes",
            0xBL to "received an invalid Retry Token in a client Initial",
            0xCL to "the application or application protocol caused the connection to be closed during the handshake",
            0xDL to "received more data in CRYPTO frames than can be buffered",
            0xEL to "key update error",
            0xFL to "the endpoint has reached the confidentiality or integrity limit for the AEAD algorithm",
            0x10L to "no viable network path exists",
        )
    }
}

/**
 * Transport-level errors occur when a peer violates the protocol specification
 * (quinn `transport_error::Error`, transport_error.rs:11).
 *
 * An exception so the connection layer can propagate it the way quinn uses `?`.
 */
class TransportError(
    /** Type of error. */
    val code: TransportErrorCode,
    /** Frame type that triggered the error. */
    var frame: FrameType? = null,
    /** Human-readable explanation of the reason. */
    val reason: String = "",
) : Exception() {

    override val message: String
        get() = buildString {
            append(code.description)
            frame?.let { append(" in ").append(it.displayName) }
            if (reason.isNotEmpty()) append(": ").append(reason)
        }

    override fun equals(other: Any?): Boolean =
        other is TransportError && other.code == code && other.frame == frame && other.reason == reason

    override fun hashCode(): Int = (code.hashCode() * 31 + frame.hashCode()) * 31 + reason.hashCode()

    override fun toString(): String = "TransportError(code=$code, frame=$frame, reason=$reason)"

    companion object {
        fun of(code: TransportErrorCode): TransportError = TransportError(code)

        fun NO_ERROR(reason: String) = TransportError(TransportErrorCode.NO_ERROR, null, reason)
        fun INTERNAL_ERROR(reason: String) = TransportError(TransportErrorCode.INTERNAL_ERROR, null, reason)
        fun CONNECTION_REFUSED(reason: String) = TransportError(TransportErrorCode.CONNECTION_REFUSED, null, reason)
        fun FLOW_CONTROL_ERROR(reason: String) = TransportError(TransportErrorCode.FLOW_CONTROL_ERROR, null, reason)
        fun STREAM_LIMIT_ERROR(reason: String) = TransportError(TransportErrorCode.STREAM_LIMIT_ERROR, null, reason)
        fun STREAM_STATE_ERROR(reason: String) = TransportError(TransportErrorCode.STREAM_STATE_ERROR, null, reason)
        fun FINAL_SIZE_ERROR(reason: String) = TransportError(TransportErrorCode.FINAL_SIZE_ERROR, null, reason)
        fun FRAME_ENCODING_ERROR(reason: String) = TransportError(TransportErrorCode.FRAME_ENCODING_ERROR, null, reason)
        fun TRANSPORT_PARAMETER_ERROR(reason: String) = TransportError(TransportErrorCode.TRANSPORT_PARAMETER_ERROR, null, reason)
        fun CONNECTION_ID_LIMIT_ERROR(reason: String) = TransportError(TransportErrorCode.CONNECTION_ID_LIMIT_ERROR, null, reason)
        fun PROTOCOL_VIOLATION(reason: String) = TransportError(TransportErrorCode.PROTOCOL_VIOLATION, null, reason)
        fun INVALID_TOKEN(reason: String) = TransportError(TransportErrorCode.INVALID_TOKEN, null, reason)
        fun APPLICATION_ERROR(reason: String) = TransportError(TransportErrorCode.APPLICATION_ERROR, null, reason)
        fun CRYPTO_BUFFER_EXCEEDED(reason: String) = TransportError(TransportErrorCode.CRYPTO_BUFFER_EXCEEDED, null, reason)
        fun KEY_UPDATE_ERROR(reason: String) = TransportError(TransportErrorCode.KEY_UPDATE_ERROR, null, reason)
        fun AEAD_LIMIT_REACHED(reason: String) = TransportError(TransportErrorCode.AEAD_LIMIT_REACHED, null, reason)
        fun NO_VIABLE_PATH(reason: String) = TransportError(TransportErrorCode.NO_VIABLE_PATH, null, reason)
    }
}
