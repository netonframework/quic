package neton.quic

import neton.quic.proto.ConnectionError
import neton.quic.proto.VarInt

// The errors of the driver API (quinn `send_stream.rs`, `recv_stream.rs`, `connection.rs`).
//
// ⚖️ quinn returns `Result<T, E>` from futures; a suspending Kotlin API throws. Each error enum is a sealed exception
// class with the same variants. Only terminal outcomes are thrown: "would block" is a suspension, never an exception.

/** Errors that arise from writing to a stream (send_stream.rs:325). */
sealed class WriteError(message: String) : Exception(message) {
    /** The peer is no longer accepting data on this stream. Carries an application-defined error code. */
    class Stopped(val errorCode: VarInt) : WriteError("sending stopped by peer: error $errorCode") {
        override fun equals(other: Any?): Boolean = other is Stopped && other.errorCode == errorCode
        override fun hashCode(): Int = errorCode.hashCode()
    }

    /** The connection was lost. */
    class ConnectionLost(val error: ConnectionError) : WriteError("connection lost") {
        override fun equals(other: Any?): Boolean = other is ConnectionLost && other.error == error
        override fun hashCode(): Int = error.hashCode()
    }

    /** The stream has already been finished or reset. */
    class ClosedStream : WriteError("closed stream") {
        override fun equals(other: Any?): Boolean = other is ClosedStream
        override fun hashCode(): Int = 1
    }

    /** This was a 0-RTT stream and the server rejected it (clients only). */
    class ZeroRttRejected : WriteError("0-RTT rejected") {
        override fun equals(other: Any?): Boolean = other is ZeroRttRejected
        override fun hashCode(): Int = 2
    }
}

/** Errors that arise while monitoring for a send stream stop from the peer (send_stream.rs:380). */
sealed class StoppedError(message: String) : Exception(message) {
    /** The connection was lost. */
    class ConnectionLost(val error: ConnectionError) : StoppedError("connection lost") {
        override fun equals(other: Any?): Boolean = other is ConnectionLost && other.error == error
        override fun hashCode(): Int = error.hashCode()
    }

    /** This was a 0-RTT stream and the server rejected it (clients only). */
    class ZeroRttRejected : StoppedError("0-RTT rejected") {
        override fun equals(other: Any?): Boolean = other is ZeroRttRejected
        override fun hashCode(): Int = 2
    }

    /** quinn `From<StoppedError> for WriteError`. */
    fun toWriteError(): WriteError = when (this) {
        is ConnectionLost -> WriteError.ConnectionLost(error)
        is ZeroRttRejected -> WriteError.ZeroRttRejected()
    }
}

/** Errors that arise from reading from a stream (recv_stream.rs:620). */
sealed class ReadError(message: String) : Exception(message) {
    /** The peer abandoned transmitting data on this stream. Carries an application-defined error code. */
    class Reset(val errorCode: VarInt) : ReadError("stream reset by peer: error $errorCode") {
        override fun equals(other: Any?): Boolean = other is Reset && other.errorCode == errorCode
        override fun hashCode(): Int = errorCode.hashCode()
    }

    /** The connection was lost. */
    class ConnectionLost(val error: ConnectionError) : ReadError("connection lost") {
        override fun equals(other: Any?): Boolean = other is ConnectionLost && other.error == error
        override fun hashCode(): Int = error.hashCode()
    }

    /** The stream has already been stopped, finished, or reset. */
    class ClosedStream : ReadError("closed stream") {
        override fun equals(other: Any?): Boolean = other is ClosedStream
        override fun hashCode(): Int = 1
    }

    /** Attempted an ordered read following an unordered read. */
    class IllegalOrderedRead : ReadError("ordered read after unordered read") {
        override fun equals(other: Any?): Boolean = other is IllegalOrderedRead
        override fun hashCode(): Int = 2
    }

    /** This was a 0-RTT stream and the server rejected it (clients only). */
    class ZeroRttRejected : ReadError("0-RTT rejected") {
        override fun equals(other: Any?): Boolean = other is ZeroRttRejected
        override fun hashCode(): Int = 3
    }
}

/** Errors that arise while waiting for a stream to be reset (recv_stream.rs:685). */
sealed class ResetError(message: String) : Exception(message) {
    /** The connection was lost. */
    class ConnectionLost(val error: ConnectionError) : ResetError("connection lost") {
        override fun equals(other: Any?): Boolean = other is ConnectionLost && other.error == error
        override fun hashCode(): Int = error.hashCode()
    }

    /** This was a 0-RTT stream and the server rejected it (clients only). */
    class ZeroRttRejected : ResetError("0-RTT rejected") {
        override fun equals(other: Any?): Boolean = other is ZeroRttRejected
        override fun hashCode(): Int = 3
    }
}

/** Errors that arise from reading from a stream into an exactly sized buffer (recv_stream.rs:755). */
sealed class ReadExactError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The stream finished before all bytes were read; carries the number of bytes that were read. */
    class FinishedEarly(val read: Int) : ReadExactError("stream finished early ($read bytes read)") {
        override fun equals(other: Any?): Boolean = other is FinishedEarly && other.read == read
        override fun hashCode(): Int = read
    }

    /** A read error occurred (quinn `ReadExactError::ReadError`). */
    class Read(val error: ReadError) : ReadExactError(error.message ?: "read error", error) {
        override fun equals(other: Any?): Boolean = other is Read && other.error == error
        override fun hashCode(): Int = error.hashCode()
    }
}

/** Errors from [RecvStream.readToEnd] (recv_stream.rs:585). */
sealed class ReadToEndError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** An error occurred during reading. */
    class Read(val error: ReadError) : ReadToEndError("read error: ${error.message}", error) {
        override fun equals(other: Any?): Boolean = other is Read && other.error == error
        override fun hashCode(): Int = error.hashCode()
    }

    /** The stream is larger than the user-supplied limit. */
    class TooLong : ReadToEndError("stream too long") {
        override fun equals(other: Any?): Boolean = other is TooLong
        override fun hashCode(): Int = 1
    }
}

/** Errors that can arise when sending a datagram (connection.rs:1300). */
sealed class SendDatagramError(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** The peer does not support receiving datagram frames. */
    class UnsupportedByPeer : SendDatagramError("datagrams not supported by peer") {
        override fun equals(other: Any?): Boolean = other is UnsupportedByPeer
        override fun hashCode(): Int = 1
    }

    /** Datagram support is disabled locally. */
    class Disabled : SendDatagramError("datagram support disabled") {
        override fun equals(other: Any?): Boolean = other is Disabled
        override fun hashCode(): Int = 2
    }

    /**
     * The datagram is larger than the connection can currently accommodate: the path MTU minus overhead or the limit
     * advertised by the peer has been exceeded.
     */
    class TooLarge : SendDatagramError("datagram too large") {
        override fun equals(other: Any?): Boolean = other is TooLarge
        override fun hashCode(): Int = 3
    }

    /** The connection was lost. */
    class ConnectionLost(val error: ConnectionError) : SendDatagramError("connection lost", error) {
        override fun equals(other: Any?): Boolean = other is ConnectionLost && other.error == error
        override fun hashCode(): Int = error.hashCode()
    }
}
