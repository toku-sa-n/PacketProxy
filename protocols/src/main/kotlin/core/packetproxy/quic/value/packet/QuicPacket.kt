/*
 * Copyright 2022 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package packetproxy.quic.value.packet

import java.nio.ByteBuffer

open class QuicPacket protected constructor(type: Byte) {
  val maskedType: Byte = type
  var type: Byte = type
    protected set

  var origPnLength: Int = (type.toInt() and 0x03) + 1
    protected set

  protected constructor(buffer: ByteBuffer) : this(buffer.get())

  protected enum class PacketHeaderType {
    LongHeaderType,
    ShortHeaderType,
  }

  protected fun unmaskType(headerType: PacketHeaderType, maskKey: ByteArray) {
    type = xor(maskedType, headerType, maskKey)
    origPnLength = (type.toInt() and 0x03) + 1
  }

  protected fun getType(newlyPnLength: Int): Byte {
    val lengthCleared = (type.toInt() and 0xfc).toByte()
    return (lengthCleared.toInt() or (newlyPnLength - 1)).toByte()
  }

  protected fun getMaskedType(
    newlyPnLength: Int,
    headerType: PacketHeaderType,
    maskKey: ByteArray,
  ): Byte = xor(getType(newlyPnLength), headerType, maskKey)

  protected open fun getBytes(): ByteArray = byteArrayOf(type)

  protected open fun getBytes(newlyPnLength: Int): ByteArray = byteArrayOf(getType(newlyPnLength))

  protected fun getMaskedBytes(
    newlyPnLength: Int,
    headerType: PacketHeaderType,
    maskKey: ByteArray,
  ): ByteArray = byteArrayOf(getMaskedType(newlyPnLength, headerType, maskKey))

  protected open fun size(): Int = 1

  companion object {
    private fun xor(type: Byte, headerType: PacketHeaderType, maskKey: ByteArray): Byte {
      val leftHand: Byte
      val rightHand: Byte
      if (headerType == PacketHeaderType.ShortHeaderType) {
        leftHand = (type.toInt() and 0xe0).toByte()
        rightHand = ((type.toInt() xor maskKey[0].toInt()) and 0x1f).toByte()
      } else {
        leftHand = (type.toInt() and 0xf0).toByte()
        rightHand = ((type.toInt() xor maskKey[0].toInt()) and 0x0f).toByte()
      }
      return (leftHand.toInt() or rightHand.toInt()).toByte()
    }
  }
}
