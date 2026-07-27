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
package packetproxy.extensions.samplehttp

import packetproxy.extensions.samplehttp.encoder.SampleHTTP
import packetproxy.model.Extension

class SampleEncoders : Extension {
  constructor() : super() {
    this.setName("Sample Extension Encoders")
  }

  constructor(name: String?, path: String?) : super(name ?: "", path ?: "") {
    this.setName("Sample Extension Encoders")
  }

  override fun getEncoders(): MutableMap<String, Class<*>> =
    mutableMapOf("SampleHTTP from extension" to SampleHTTP::class.java)
}
