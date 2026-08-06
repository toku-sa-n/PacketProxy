/*
 * Copyright 2026 DeNA Co., Ltd.
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
package packetproxy.gui

import com.formdev.flatlaf.FlatDarculaLaf
import com.formdev.flatlaf.FlatIntelliJLaf
import java.util.concurrent.TimeUnit
import packetproxy.common.Utils
import packetproxy.common.i18nString
import packetproxy.model.ConfigString
import packetproxy.model.Configs

enum class ThemeMode(val configValue: String, val label: String) {
  LIGHT("light", "Light"),
  DARK("dark", "Dark"),
  SYSTEM("system", "System");

  fun localizedLabel(): String = i18nString(label)

  companion object {
    fun of(configValue: String): ThemeMode =
      entries.firstOrNull { it.configValue == configValue.lowercase() } ?: LIGHT
  }
}

/** Stores the color theme preference and installs the matching FlatLaf look and feel. */
class ThemeManager(configs: Configs) {
  private val configTheme = ConfigString(configs, "UITheme")
  private var systemDark: Boolean? = null

  fun getMode(): ThemeMode {
    var stored = configTheme.getString()
    if (stored.isEmpty()) {
      configTheme.setString(ThemeMode.LIGHT.configValue)
      return ThemeMode.LIGHT
    }
    return ThemeMode.of(stored)
  }

  fun setMode(mode: ThemeMode) {
    configTheme.setString(mode.configValue)
  }

  fun resolveEffectiveDark(): Boolean =
    when (getMode()) {
      ThemeMode.LIGHT -> false
      ThemeMode.DARK -> true
      ThemeMode.SYSTEM -> isSystemDark()
    }

  fun applyLookAndFeel() {
    if (resolveEffectiveDark()) {
      FlatDarculaLaf.setup()
      return
    }
    FlatIntelliJLaf.setup()
  }

  /** Queries the OS appearance setting. Platforms without a known query are treated as light. */
  private fun isSystemDark(): Boolean {
    systemDark?.let {
      return it
    }
    var detected =
      when {
        Utils.isMac() -> readCommandOutput("defaults", "read", "-g", "AppleInterfaceStyle")
        Utils.isWindows() ->
          readCommandOutput(
            "reg",
            "query",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            "/v",
            "AppsUseLightTheme",
          )
        else -> null
      }
    var dark =
      when {
        detected == null -> false
        Utils.isMac() -> detected.contains("Dark", ignoreCase = true)
        else -> isWindowsDarkRegistryOutput(detected)
      }
    systemDark = dark
    return dark
  }

  /** `AppsUseLightTheme` の値が 0x0 のときだけダークテーマとみなす */
  private fun isWindowsDarkRegistryOutput(output: String): Boolean {
    var line =
      output.lineSequence().firstOrNull { it.contains("AppsUseLightTheme") } ?: return false
    return line.trim().endsWith("0x0")
  }

  private fun readCommandOutput(vararg command: String): String? =
    try {
      var process = ProcessBuilder(*command).redirectErrorStream(true).start()
      var output = process.inputStream.bufferedReader().use { it.readText() }
      if (!process.waitFor(SYSTEM_QUERY_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
        process.destroy()
        null
      } else if (process.exitValue() != 0) {
        null
      } else {
        output
      }
    } catch (_: Exception) {
      null
    }

  companion object {
    private const val SYSTEM_QUERY_TIMEOUT_SECONDS = 2L
  }
}
