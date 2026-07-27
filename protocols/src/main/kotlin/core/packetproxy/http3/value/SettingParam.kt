/*
 * Copyright 2023 DeNA Co., Ltd.
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
package packetproxy.http3.value

import java.io.ByteArrayOutputStream
import java.io.IOException
import packetproxy.quic.value.VariableLengthInteger

enum class SettingParam(val id: Long, @JvmField val defaultValue: Long) {
  QpackMaxTableCapacity(0x01, 0),
  MaxFieldSectionSize(0x06, Long.MAX_VALUE),
  QpackBlockedStreams(0x07, 0),
  EnableConnectProtocol(0x08, 0),
  H3Datagram(0x33, 0),
  H3DatagramOld(0x276, 0),
  EnableMetaData(0x4d44, 0);

  fun idEqualsTo(id: Long): Boolean = this.id == id

  fun defaultValueEqualsTo(value: Long): Boolean = this.defaultValue == value

  @Throws(IOException::class)
  fun getBytesIfNotDefaultValue(value: Long): ByteArray {
    val retBytes = ByteArrayOutputStream()
    if (this.defaultValue != value) {
      retBytes.write(VariableLengthInteger.of(this.id).bytes)
      retBytes.write(VariableLengthInteger.of(value).bytes)
    }
    return retBytes.toByteArray()
  }
}
