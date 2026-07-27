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

data class Setting(
  val qpackMaxTableCapacity: Long,
  val maxFieldSectionSize: Long,
  val qpackBlockedStreams: Long,
  val enableConnectProtocol: Long,
  val h3Datagram: Long,
  val h3DatagramOld: Long,
  val enableMetaData: Long,
) {
  class SettingBuilder {
    private var qpackMaxTableCapacity = SettingParam.QpackMaxTableCapacity.defaultValue
    private var maxFieldSectionSize = SettingParam.MaxFieldSectionSize.defaultValue
    private var qpackBlockedStreams = SettingParam.QpackBlockedStreams.defaultValue
    private var enableConnectProtocol = SettingParam.EnableConnectProtocol.defaultValue
    private var h3Datagram = SettingParam.H3Datagram.defaultValue
    private var h3DatagramOld = SettingParam.H3DatagramOld.defaultValue
    private var enableMetaData = SettingParam.EnableMetaData.defaultValue

    fun qpackMaxTableCapacity(qpackMaxTableCapacity: Long): SettingBuilder = apply {
      this.qpackMaxTableCapacity = qpackMaxTableCapacity
    }

    fun maxFieldSectionSize(maxFieldSectionSize: Long): SettingBuilder = apply {
      this.maxFieldSectionSize = maxFieldSectionSize
    }

    fun qpackBlockedStreams(qpackBlockedStreams: Long): SettingBuilder = apply {
      this.qpackBlockedStreams = qpackBlockedStreams
    }

    fun enableConnectProtocol(enableConnectProtocol: Long): SettingBuilder = apply {
      this.enableConnectProtocol = enableConnectProtocol
    }

    fun h3Datagram(h3Datagram: Long): SettingBuilder = apply { this.h3Datagram = h3Datagram }

    fun h3DatagramOld(h3DatagramOld: Long): SettingBuilder = apply {
      this.h3DatagramOld = h3DatagramOld
    }

    fun enableMetaData(enableMetaData: Long): SettingBuilder = apply {
      this.enableMetaData = enableMetaData
    }

    fun build(): Setting =
      Setting(
        qpackMaxTableCapacity = qpackMaxTableCapacity,
        maxFieldSectionSize = maxFieldSectionSize,
        qpackBlockedStreams = qpackBlockedStreams,
        enableConnectProtocol = enableConnectProtocol,
        h3Datagram = h3Datagram,
        h3DatagramOld = h3DatagramOld,
        enableMetaData = enableMetaData,
      )
  }

  companion object {
    @JvmStatic fun builder(): SettingBuilder = SettingBuilder()

    @JvmStatic fun generateWithDefaultValue(): Setting = builder().build()
  }
}
