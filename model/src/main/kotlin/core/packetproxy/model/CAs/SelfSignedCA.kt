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
package packetproxy.model.CAs

import packetproxy.common.*

class SelfSignedCA : CA {
  companion object {
    private val name = "Temp CA (for SelfSigned Test)"
    private val desc = i18nString("self sigend CA (for security test purpose)")
    private val keyStorePath = "/certificates/user.ks"
  }

  @Throws(Exception::class)
  constructor() : super() {
    super.loadFromResource(keyStorePath)
  }

  override fun getName(): String = name

  override fun getUTF8Name(): String = desc

  override fun toString(): String = "SelfSignedCA [name=$name, desc=$desc]"
}
