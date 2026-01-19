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
package packetproxy.extensions.securityheaders

/** Represents the result of a security header check. */
class SecurityCheckResult(status: Status?, displayValue: String?, rawValue: String?) {
  enum class Status {
    OK,
    FAIL,
    WARN,
  }

  private val status: Status
  private val displayValue: String
  private val rawValue: String

  init {
    require(status != null) { "status must not be null" }
    this.status = status
    this.displayValue = displayValue ?: status.name
    this.rawValue = rawValue ?: ""
  }

  fun getStatus(): Status = status

  fun getDisplayValue(): String = displayValue

  fun getRawValue(): String = rawValue

  fun isOk(): Boolean = status == Status.OK

  fun isFail(): Boolean = status == Status.FAIL

  fun isWarn(): Boolean = status == Status.WARN

  companion object {
    @JvmStatic
    fun ok(displayValue: String?, rawValue: String?): SecurityCheckResult {
      return SecurityCheckResult(Status.OK, displayValue, rawValue)
    }

    @JvmStatic
    fun fail(displayValue: String?, rawValue: String?): SecurityCheckResult {
      return SecurityCheckResult(Status.FAIL, displayValue, rawValue)
    }

    @JvmStatic
    fun warn(displayValue: String?, rawValue: String?): SecurityCheckResult {
      return SecurityCheckResult(Status.WARN, displayValue, rawValue)
    }
  }
}
