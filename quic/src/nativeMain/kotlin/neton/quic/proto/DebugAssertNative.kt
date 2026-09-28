package neton.quic.proto

import kotlin.experimental.ExperimentalNativeApi

@OptIn(ExperimentalNativeApi::class)
internal actual val DEBUG_ASSERTIONS: Boolean = Platform.isDebugBinary
