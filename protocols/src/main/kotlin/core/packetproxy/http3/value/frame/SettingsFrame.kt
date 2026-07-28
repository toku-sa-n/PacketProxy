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
package packetproxy.http3.value.frame

import com.google.common.collect.ImmutableList
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import packetproxy.http3.utils.parseVarInt
import packetproxy.http3.utils.readSimpleBytes
import packetproxy.http3.value.Setting
import packetproxy.http3.value.SettingParam
import packetproxy.quic.value.VariableLengthInteger
import packetproxy.util.errWithStackTrace

class SettingsFrame private constructor(private val setting: Setting) : Frame {
  private val type: Long = TYPE

  override fun getType(): Long = type

  fun getSetting(): Setting = setting

  override fun getBytes(): ByteArray {
    val frameStream = ByteArrayOutputStream()
    try {
      val dataStream = ByteArrayOutputStream()

      if (setting.qpackMaxTableCapacity != SettingParam.QpackMaxTableCapacity.defaultValue) {
        dataStream.write(VariableLengthInteger.of(SettingParam.QpackMaxTableCapacity.id).bytes)
        dataStream.write(VariableLengthInteger.of(setting.qpackMaxTableCapacity).bytes)
      }
      if (setting.qpackBlockedStreams != SettingParam.QpackBlockedStreams.defaultValue) {
        dataStream.write(VariableLengthInteger.of(SettingParam.QpackBlockedStreams.id).bytes)
        dataStream.write(VariableLengthInteger.of(setting.qpackBlockedStreams).bytes)
      }
      if (setting.maxFieldSectionSize != SettingParam.MaxFieldSectionSize.defaultValue) {
        dataStream.write(VariableLengthInteger.of(SettingParam.MaxFieldSectionSize.id).bytes)
        dataStream.write(VariableLengthInteger.of(setting.maxFieldSectionSize).bytes)
      }
      if (setting.enableConnectProtocol != SettingParam.EnableConnectProtocol.defaultValue) {
        dataStream.write(VariableLengthInteger.of(SettingParam.EnableConnectProtocol.id).bytes)
        dataStream.write(VariableLengthInteger.of(setting.enableConnectProtocol).bytes)
      }
      if (setting.h3Datagram != SettingParam.H3Datagram.defaultValue) {
        dataStream.write(VariableLengthInteger.of(SettingParam.H3Datagram.id).bytes)
        dataStream.write(VariableLengthInteger.of(setting.h3Datagram).bytes)
      }
      if (setting.h3DatagramOld != SettingParam.H3DatagramOld.defaultValue) {
        dataStream.write(VariableLengthInteger.of(SettingParam.H3DatagramOld.id).bytes)
        dataStream.write(VariableLengthInteger.of(setting.h3DatagramOld).bytes)
      }
      if (setting.enableMetaData != SettingParam.EnableMetaData.defaultValue) {
        dataStream.write(VariableLengthInteger.of(SettingParam.EnableMetaData.id).bytes)
        dataStream.write(VariableLengthInteger.of(setting.enableMetaData).bytes)
      }

      val data = dataStream.toByteArray()
      frameStream.write(VariableLengthInteger.of(type).bytes)
      frameStream.write(VariableLengthInteger.of(data.size.toLong()).bytes)
      frameStream.write(data)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }

    return frameStream.toByteArray()
  }

  companion object {
    @JvmField val TYPE: Long = 0x04

    @JvmStatic fun supportedTypes(): List<Long> = ImmutableList.of(TYPE)

    @JvmStatic
    fun generateSettingsFrameWithDefaultValue(): SettingsFrame =
      SettingsFrame(Setting.generateWithDefaultValue())

    @JvmStatic fun of(setting: Setting): SettingsFrame = SettingsFrame(setting)

    @JvmStatic
    @Throws(Exception::class)
    fun parse(buffer: ByteBuffer): SettingsFrame {
      parseVarInt(buffer)
      val frameLength = parseVarInt(buffer)
      val frameData = readSimpleBytes(buffer, frameLength)

      val settingsDataBuffer = ByteBuffer.wrap(frameData)

      var settingBuilder = Setting.builder()
      while (settingsDataBuffer.hasRemaining()) {
        val id = parseVarInt(settingsDataBuffer)
        val value = parseVarInt(settingsDataBuffer)
        settingBuilder =
          when {
            SettingParam.QpackMaxTableCapacity.idEqualsTo(id) ->
              settingBuilder.qpackMaxTableCapacity(value)
            SettingParam.MaxFieldSectionSize.idEqualsTo(id) ->
              settingBuilder.maxFieldSectionSize(value)
            SettingParam.QpackBlockedStreams.idEqualsTo(id) ->
              settingBuilder.qpackBlockedStreams(value)
            SettingParam.EnableConnectProtocol.idEqualsTo(id) ->
              settingBuilder.enableConnectProtocol(value)
            SettingParam.H3Datagram.idEqualsTo(id) -> settingBuilder.h3Datagram(value)
            SettingParam.H3DatagramOld.idEqualsTo(id) -> settingBuilder.h3DatagramOld(value)
            SettingParam.EnableMetaData.idEqualsTo(id) -> settingBuilder.enableMetaData(value)
            else -> settingBuilder // Grease Setting. Just ignored.
          }
      }
      return SettingsFrame(settingBuilder.build())
    }
  }
}
