/*
 * Copyright 2025 DeNA Co., Ltd.
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
package packetproxy.util

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.LoggerContext
import ch.qos.logback.classic.encoder.PatternLayoutEncoder
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.ConsoleAppender
import ch.qos.logback.core.FileAppender
import core.packetproxy.util.readUtf8Line
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*
import javax.swing.JComponent
import kotlinx.coroutines.delay
import kotlinx.coroutines.yield
import org.slf4j.LoggerFactory

/**
 * Application-scoped logging backend.
 *
 * UI log sinks are owned by the composition root and injected where they are needed.
 */
class Logging {
  private val dtf: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss")
  private val logger = LoggerFactory.getLogger("")
  private var isGulp: Boolean = false
  @Volatile private var logSink: LogSink = NoOpLogSink()

  // log出力先のファイルの絶対PATH
  private val logFilePath by lazy {
    val projectRoot = System.getProperty("app.home") ?: "."
    val logDir = File(projectRoot, "logs")
    if (!logDir.exists()) logDir.mkdirs()
    "${logDir.absolutePath}/gulp.log"
  }

  private val logFile by lazy {
    val logFile = File(logFilePath)
    if (!logFile.exists()) throw IOException("not found: ${logFile.absolutePath}")
    logFile
  }

  fun setLogSinkInternal(sink: LogSink) {
    logSink = sink
  }

  fun createLogPanelInternal(): JComponent = logSink.createPanel()

  fun getLogTextInternal(): String = logSink.getLogText()

  fun initInternal(isGulp: Boolean) {
    this.isGulp = isGulp
    val context = LoggerFactory.getILoggerFactory() as LoggerContext

    context.reset()

    val encoder =
      PatternLayoutEncoder().apply {
        this.context = context
        pattern = "%msg%n"
        start()
      }

    val appender =
      if (isGulp) {
        FileAppender<ILoggingEvent>().apply {
          this.context = context
          name = "FILE"
          file = logFilePath
          isAppend = false
          this.encoder = encoder
          start()
        }
      } else {
        ConsoleAppender<ILoggingEvent>().apply {
          this.context = context
          name = "CONSOLE"
          this.encoder = encoder
          start()
        }
      }

    val rootLogger = context.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME)
    rootLogger.addAppender(appender)
    // ormliteなどのdebugログを抑制するため、WARN未満は出力しない
    rootLogger.level = Level.WARN
  }

  @Throws(IllegalFormatException::class)
  fun logInternal(format: Any, vararg args: Any?) {
    val fs = formatString(format, *args)

    // WARN未満は出力されないためwarnで出力する
    logger.warn(fs)
    if (isGulp) return
    logSink.append(fs)
  }

  @Throws(IllegalFormatException::class)
  fun errInternal(format: Any, vararg args: Any?) {
    val fs = formatString(format, *args)

    logger.error(fs)
    if (isGulp) return
    logSink.appendErr(fs)
  }

  /** 別のログが挟まらないように一塊にした上で１度に出力する */
  @Throws(IllegalFormatException::class)
  fun errWithStackTraceInternal(e: Throwable) {
    val sb = StringBuilder()
    sb.append(e.toString())

    for (element in e.stackTrace) {
      sb.append("\n$element")
    }
    errInternal(sb.toString())
  }

  /** logの継続出力を行う */
  suspend fun tailLog() {
    RandomAccessFile(logFile, "r").use { raf ->
      // ブロッキング実行される場合は先頭、そうでない場合は末尾30行目から出力を開始する
      raf.seek(0)

      // 新しい追加分を追跡する
      while (true) {
        yield()
        printRemaining(raf)
        delay(100)
      }
    }
  }

  /** raf.seekされた箇所から末尾までを出力する */
  private fun printRemaining(raf: RandomAccessFile) {
    val initialLength = logFile.length()
    while (raf.filePointer < initialLength) {
      val line = raf.readUtf8Line() ?: continue
      println(LogLineStyle.colorizeForConsole(line))
    }
  }

  /** 第１引数が文字列でないなどの場合はtoString()を実行する 第１引数が文字列かつ第２引数移行が正しく指定されている場合のみフォーマット指定子としての解釈を行う */
  private fun formatString(format: Any, vararg args: Any?): String {
    val dateTime = dtf.format(LocalDateTime.now()) + "     "
    val indent = " ".repeat(dateTime.length)

    val msg =
      if (format is String && args.isNotEmpty()) {
        try {
          format.format(*args)
        } catch (e: Exception) {
          format
        }
      } else {
        format.toString()
      }

    return dateTime + msg.replace("\n", "\n$indent")
  }

  companion object {
    /** Registers the application-scoped [Logging] used by process-wide fallback helpers. */
    @JvmStatic
    fun installFallback(instance: Logging) {
      processWideLogging = instance
    }

    @JvmStatic fun log(format: Any, vararg args: Any?) = packetproxy.util.log(format, *args)

    @JvmStatic fun err(format: Any, vararg args: Any?) = packetproxy.util.err(format, *args)

    @JvmStatic fun errWithStackTrace(e: Throwable) = packetproxy.util.errWithStackTrace(e)
  }
}

/**
 * Process-wide fallback for code paths that have not received an application-scoped [Logging]. When
 * [Logging.installFallback] has been called, messages reach the UI [LogSink].
 */
fun log(format: Any, vararg args: Any?) {
  var instance = processWideLogging
  if (instance != null) {
    instance.logInternal(format, *args)
    return
  }
  LoggerFactory.getLogger("").warn(formatForFallback(format, *args))
}

fun err(format: Any, vararg args: Any?) {
  var instance = processWideLogging
  if (instance != null) {
    instance.errInternal(format, *args)
    return
  }
  LoggerFactory.getLogger("").error(formatForFallback(format, *args))
}

fun errWithStackTrace(e: Throwable) {
  var instance = processWideLogging
  if (instance != null) {
    instance.errWithStackTraceInternal(e)
    return
  }
  err(e.stackTraceToString())
}

/** Returns retained log text from the installed [Logging] sink, or empty if none is installed. */
fun getLogText(): String = processWideLogging?.getLogTextInternal() ?: ""

@Volatile private var processWideLogging: Logging? = null

private fun formatForFallback(format: Any, vararg args: Any?): String =
  if (format is String && args.isNotEmpty()) {
    try {
      format.format(*args)
    } catch (_: Exception) {
      format
    }
  } else {
    format.toString()
  }
