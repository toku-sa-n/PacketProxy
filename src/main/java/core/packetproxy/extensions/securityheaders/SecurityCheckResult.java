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
package packetproxy.extensions.securityheaders;

/** Represents the result of a security header check. */
public class SecurityCheckResult {

	public enum Status {
		OK, FAIL, WARN
	}

	private final Status status;
	private final String displayValue;
	private final String rawValue;

	public SecurityCheckResult(Status status, String displayValue, String rawValue) {
		if (status == null) {
			throw new IllegalArgumentException("status must not be null");
		}
		this.status = status != null ? status : Status.FAIL;
		this.displayValue = displayValue != null ? displayValue : this.status.name();
		this.rawValue = rawValue != null ? rawValue : "";
	}

	public static SecurityCheckResult ok(String displayValue, String rawValue) {
		return new SecurityCheckResult(Status.OK, displayValue, rawValue);
	}

	public static SecurityCheckResult fail(String displayValue, String rawValue) {
		return new SecurityCheckResult(Status.FAIL, displayValue, rawValue);
	}

	public static SecurityCheckResult warn(String displayValue, String rawValue) {
		return new SecurityCheckResult(Status.WARN, displayValue, rawValue);
	}

	public Status getStatus() {
		return status;
	}

	public String getDisplayValue() {
		return displayValue;
	}

	public String getRawValue() {
		return rawValue;
	}

	public boolean isOk() {
		return status == Status.OK;
	}

	public boolean isFail() {
		return status == Status.FAIL;
	}

	public boolean isWarn() {
		return status == Status.WARN;
	}
}
