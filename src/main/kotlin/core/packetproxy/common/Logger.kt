/*
 * Copyright 2019 DeNA Co., Ltd.
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
package packetproxy.common

import java.io.File
import packetproxy.model.Packet

open class Logger(private val packets: List<Packet>) {
  private var log_dir: String = DEFAULT_LOG_DIR
  private var log_ext: String = DEFAULT_LOG_EXT
  private var file_title: String? = null

  init {
    val f = File(DEFAULT_LOG_DIR)
    if (!f.exists()) f.mkdirs()
  }

  fun appendLogDir(append_log_dir: String) {
    // logs/appended_log_dir/以下に保存みたいなことをする
    // windowsにも対応できてるはず
    log_dir = listOf(DEFAULT_LOG_DIR, append_log_dir).joinToString(File.separator)
  }

  fun setFileTitle(file_title: String) {
    this.file_title = file_title
  }

  @Throws(Exception::class)
  fun outputToFile(filename: String?): String {
    var outFilename = filename
    if (outFilename == null) {
      outFilename = listOf(log_dir, createFileName()).joinToString(File.separator)
    }
    val sb = loggingProcess()
    Utils.writefile(outFilename, sb.toString().toByteArray())
    return outFilename
  }

  /** ロギングのフォーマットを決定する部分 継承して使ってくれれば好きな出力にできる。はず。 */
  @Throws(Exception::class)
  protected open fun loggingProcess(): StringBuilder {
    val sb = StringBuilder()
    for (packet in packets) {
      sb.append(packet.getClient().toString())
      sb.append(" --> ")
      sb.append(packet.getServer().toString())
      sb.append("\r\n")
      sb.append("--------------------------------\r\n")
      if (packet.getDecodedData().size < 5000) {
        sb.append(String(packet.getDecodedData()))
      } else {
        sb.append(String(packet.getDecodedData(), 0, 5000, Charsets.UTF_8))
        sb.append("...(snipped)...")
      }
      sb.append("\r\n")
      sb.append("--------------------------------\r\n")
      sb.append("\r\n")
    }
    return sb
  }

  private fun createFileName(): String {
    return if (file_title == null) {
      "log_${System.currentTimeMillis()}.$log_ext"
    } else {
      file_title + log_ext
    }
  }

  private companion object {
    val DEFAULT_LOG_DIR = System.getProperty("user.home") + "/.packetproxy/logs"
    const val DEFAULT_LOG_EXT = "txt"
  }
}
