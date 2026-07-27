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

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress

class RawEndpoint(
  private val addr: InetSocketAddress,
  private val input: InputStream,
  private val output: OutputStream,
) : Endpoint {
  override fun getAddress(): InetSocketAddress = addr

  override fun getInputStream(): InputStream = input

  override fun getOutputStream(): OutputStream = output

  override fun getLocalPort(): Int = 0

  override fun getName(): String? = null
}
