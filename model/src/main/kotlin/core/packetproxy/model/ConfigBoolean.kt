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
package packetproxy.model

class ConfigBoolean(private val configs: Configs, private val key: String) {
  private var config = ensureConfig()

  fun getState(): Boolean {
    config = ensureConfig()
    return config.value == "true"
  }

  fun setState(state: Boolean) {
    config = ensureConfig()
    config.value = if (state) "true" else "false"
    configs.update(config)
  }

  private fun ensureConfig(defaultValue: String = "false"): Config {
    var current = configs.query(key)
    if (current == null) {
      configs.create(Config(key, defaultValue))
      current = configs.query(key)
    }
    return checkNotNull(current) { "Failed to ensure config key=$key" }
  }
}
