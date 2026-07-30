/*
 * Copyright 2026 DeNA Co., Ltd.
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
package packetproxy.controller

import arrow.core.None
import arrow.core.Option
import arrow.core.Some
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import packetproxy.model.InterceptModel
import packetproxy.model.InterceptOptions
import packetproxy.model.Packet
import packetproxy.model.Server

/**
 * パケットのインターセプト（傍受・改ざん・廃棄）を制御する。
 *
 * プロキシパイプライン側（received）でパケットを捕捉し、UI側（forward/drop）からの 操作決定を待機する。InterceptModel を介して UI に状態を通知し、
 * InterceptOptions のルールに基づいて対象パケットをフィルタリングする。
 * - suspend fun received(): プロキシ向け。コルーチンをサスペンドして UI 操作を待つ。
 */
class InterceptController(
  private val interceptModel: InterceptModel,
  private val interceptOptions: InterceptOptions,
  private val resendController: ResendController,
) {

  private sealed class InterceptDecision {
    data class Forward(val data: ByteArray) : InterceptDecision()

    data class ForwardMultiple(val data: ByteArray) : InterceptDecision()

    data object Drop : InterceptDecision()
  }

  private val mutex = Mutex()
  private var pendingDeferred: CompletableDeferred<InterceptDecision>? = null

  fun enableInterceptMode() {
    interceptModel.enableInterceptMode()
  }

  fun disableInterceptMode(data: ByteArray) {
    pendingDeferred?.complete(InterceptDecision.Forward(data))
    interceptModel.disableInterceptMode()
  }

  fun forward(data: ByteArray) {
    pendingDeferred?.complete(InterceptDecision.Forward(data))
  }

  @Suppress("FunctionName")
  fun forward_multiple(data: ByteArray) {
    pendingDeferred?.complete(InterceptDecision.ForwardMultiple(data))
  }

  fun drop() {
    pendingDeferred?.complete(InterceptDecision.Drop)
  }

  /**
   * received()を呼ぶ前に、対象パケットがインターセプト対象かどうかを判定する。 インターセプト対象でない場合、呼び出し側はsha1によるハッシュ比較をスキップできる
   * （received()はインターセプト対象でなければ即座にdataをそのまま返すだけで、 実際には改変されないため）。
   */
  fun shouldIntercept(
    server: Server?,
    clientPacket: Packet,
    serverPacket: Packet? = null,
  ): Boolean = isInterceptTarget(server, clientPacket, serverPacket)

  /**
   * suspend 版
   *
   * 戻り値:
   * - None = drop（ユーザーが意図した廃棄。エラーではない）
   * - Some = forward（通過。データはユーザーが改ざんしている可能性あり）
   */
  suspend fun received(
    data: ByteArray,
    server: Server?,
    clientPacket: Packet,
    serverPacket: Packet? = null,
  ): Option<ByteArray> {
    val targetPacket = serverPacket ?: clientPacket

    if (!isInterceptTarget(server, clientPacket, serverPacket)) return Some(data)

    return mutex.withLock {
      val deferred = CompletableDeferred<InterceptDecision>()
      pendingDeferred = deferred
      interceptModel.setData(data, clientPacket, serverPacket)
      try {
        when (val decision = deferred.await()) {
          is InterceptDecision.Drop -> None
          is InterceptDecision.Forward -> Some(decision.data)
          is InterceptDecision.ForwardMultiple -> {
            resendController.resend(targetPacket.getOneShotPacket(decision.data), 19, true)
            targetPacket.setResend()
            Some(decision.data)
          }
        }
      } finally {
        interceptModel.clearData()
        pendingDeferred = null
      }
    }
  }

  private fun isInterceptTarget(
    server: Server?,
    clientPacket: Packet,
    serverPacket: Packet?,
  ): Boolean {
    if (!interceptModel.isInterceptEnabled()) return false

    if (interceptOptions.isEnabled()) {
      return if (serverPacket == null) {
        interceptOptions.interceptOnRequest(server, clientPacket)
      } else {
        interceptOptions.interceptOnResponse(server, clientPacket, serverPacket)
      }
    }

    return true
  }
}
