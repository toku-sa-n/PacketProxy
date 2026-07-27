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
package packetproxy.extensions

import packetproxy.extensions.endpointoverview.EndpointOverviewExtension
import packetproxy.extensions.mcp.MCPServerExtension
import packetproxy.extensions.randomness.RandomnessExtension
import packetproxy.extensions.samplehttp.SampleEncoders
import packetproxy.extensions.securityheaders.SecurityHeadersExtension
import packetproxy.model.Extensions

object PresetExtensions {
  @JvmStatic
  fun registerAll() {
    Extensions.registerPreset(MCPServerExtension::class.java)
    Extensions.registerPreset(RandomnessExtension::class.java)
    Extensions.registerPreset(SampleEncoders::class.java)
    Extensions.registerPreset(SecurityHeadersExtension::class.java)
    Extensions.registerPreset(EndpointOverviewExtension::class.java)
  }
}
