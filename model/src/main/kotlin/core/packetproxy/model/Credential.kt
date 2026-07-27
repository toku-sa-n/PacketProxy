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

class Credential {
  // should be public for JSONIC.
  @JvmField var username: String? = null

  @JvmField var password: String? = null

  constructor() {
    // needed for JSONIC library.
  }

  constructor(username: String, password: String) {
    this.username = username
    this.password = password
  }

  fun getUsername(): String? = this.username

  fun getPassword(): String? = this.password

  override fun toString(): String = "Auth [username=$username, password=$password]"
}
