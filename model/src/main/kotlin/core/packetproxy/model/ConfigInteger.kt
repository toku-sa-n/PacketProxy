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

class ConfigInteger(
  private val configs: Configs,
  private val key: String,
  private val defaultValue: String = "0",
) {
  private var config = ensureConfig()

  fun getInteger(): Int {
    config = ensureConfig()
    return config.value!!.toInt()
  }

  fun setInteger(value: Int) {
    config = ensureConfig()
    config.value = value.toString()
    configs.update(config)
  }

  private fun ensureConfig(): Config {
    var current = configs.query(key)
    if (current == null) {
      configs.create(Config(key, defaultValue))
      current = configs.query(key)
    }
    return checkNotNull(current) { "Failed to ensure config key=$key" }
  }
}
