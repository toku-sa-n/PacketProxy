/*
 * Copyright 2022 DeNA Co., Ltd.
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
package packetproxy.http3.value

class UniStreamHeader private constructor(val type: Long) {
  companion object {
    @JvmStatic fun of(type: Long): UniStreamHeader = UniStreamHeader(type)
  }

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is UniStreamHeader) return false
    return type == other.type
  }

  override fun hashCode(): Int = type.hashCode()

  override fun toString(): String = "UniStreamHeader(type=$type)"
}
