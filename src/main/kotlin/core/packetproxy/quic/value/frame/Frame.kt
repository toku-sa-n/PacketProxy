package packetproxy.quic.value.frame

abstract class Frame {
  abstract fun getBytes(): ByteArray

  abstract fun isAckEliciting(): Boolean
}
