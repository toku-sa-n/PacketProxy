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
package packetproxy.controller

import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import java.util.function.Consumer
import javax.swing.SwingWorker
import packetproxy.Duplex
import packetproxy.DuplexAsync
import packetproxy.DuplexFactory
import packetproxy.DuplexManager
import packetproxy.EncoderManager
import packetproxy.common.I18nString
import packetproxy.encode.EncodeHTTPBase
import packetproxy.encode.Encoder
import packetproxy.http.Http
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet
import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace

class ResendController private constructor() {
  companion object {
    @Volatile private var instance: ResendController? = null

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): ResendController =
      instance ?: synchronized(this) { instance ?: ResendController().also { instance = it } }
  }

  /** レスポンスを受け取って処理する必要がないとき用 */
  @Throws(Exception::class)
  fun resend(oneshot: OneShotPacket) {
    resend(oneshot, 1)
  }

  /** レスポンスを受け取って処理する必要がないとき用 */
  @Throws(Exception::class)
  fun resend(oneshot: OneShotPacket, count: Int) {
    resend(oneshot, count, false)
  }

  /** レスポンスを受け取って処理する必要がないとき用 */
  @Throws(Exception::class)
  fun resend(oneshot: OneShotPacket, count: Int, wait: Boolean) {
    var worker: SwingWorker<Any?, OneShotPacket> = ResendWorker(oneshot, count)
    worker.execute()
    if (wait && count != 1) {
      try {
        // InterceptでForward x 20した時に先に本体が処理されると困るので待つ
        worker.get(20000, TimeUnit.MILLISECONDS)
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  /**
   * レスポンスを受け取って処理する必要があるとき用 ResendUsingNewConnectionを無名クラスでextendsしてprocessでList<OneShotPacket>受け取る
   *
   * @param worker
   */
  fun resend(worker: ResendWorker) {
    worker.execute()
  }

  open class ResendWorker : SwingWorker<Any?, OneShotPacket> {
    @JvmField protected var count: Int
    @JvmField protected var oneshot: OneShotPacket?
    @JvmField protected var oneshots: Array<OneShotPacket>?

    constructor(oneshot: OneShotPacket, count: Int) {
      this.oneshot = oneshot
      this.count = count
      oneshots = null
    }

    constructor(oneshots: Array<OneShotPacket>) {
      oneshot = null
      count = 0
      this.oneshots = oneshots
    }

    @Throws(Exception::class)
    override fun doInBackground(): Any? {
      try {
        var list = ArrayList<DataToBeSend>()
        if (oneshot != null && count > 0) {
          for (i in 0 until count) {
            var sendData = DataToBeSend(oneshot!!, Consumer { result -> publish(result) })
            list.add(sendData)
          }
        } else if (oneshots != null && oneshots!!.isNotEmpty()) {
          for (os in oneshots!!) {
            var sendData = DataToBeSend(os, Consumer { result -> publish(result) })
            list.add(sendData)
          }
        } else {
          err("Resend packet is wrong!")
          return null
        }

        list
          .filter { it.isDirectSend() }
          .forEach { sendData ->
            try {
              sendData.send()
            } catch (e: Exception) {
              errWithStackTrace(e)
            }
          }
        list
          .parallelStream()
          .filter { !it.isDirectSend() }
          .forEach { sendData ->
            try {
              sendData.send()
            } catch (e: Exception) {
              errWithStackTrace(e)
            }
          }
      } catch (e: SocketTimeoutException) {
        err("Resend Connection is timeout!")
        err("All resend packets are dropped.")
        errWithStackTrace(e)
        return null
      } catch (e: Exception) {
        errWithStackTrace(e)
        throw e
      }
      return null
    }

    private inner class DataToBeSend(
      private val oneshot: OneShotPacket,
      private val onReceived: Consumer<OneShotPacket>,
    ) {
      private var duplex: Duplex? = null
      private var preparedData: ByteArray? = null
      private var isSync = false
      private var directSend = false

      init {
        var encoder: Encoder =
          EncoderManager.getInstance().createInstance(oneshot.getEncoder()!!, oneshot.getAlpn())
        if (!encoder.useNewConnectionForResend() && !encoder.useNewEncoderForResend()) {
          directSend = true
          duplex = DuplexManager.getInstance().getDuplex(oneshot.getConn())
          preparedData = oneshot.getData()
        } else if (encoder.useNewConnectionForResend()) {
          duplex = DuplexFactory.createDuplexSyncFromOneShotPacket(oneshot)
          isSync = false
        } else {
          var originalDuplex = DuplexManager.getInstance().getDuplex(oneshot.getConn())
          if (originalDuplex == null) {
            err(
              I18nString.get(
                "[Error] tried to resend packets, but the connection was already closed."
              )
            )
          } else {
            duplex = DuplexFactory.createDuplexFromOriginalDuplex(originalDuplex, oneshot)
            if (duplex is DuplexAsync) {
              (duplex as DuplexAsync).start()
            }
            isSync = true
          }
        }
        if (duplex != null && preparedData == null) {
          preparedData = duplex!!.prepareFastSend(oneshot.getData())
        }
      }

      fun isDirectSend(): Boolean = directSend

      @Throws(Exception::class)
      fun send() {
        var currentDuplex = duplex ?: return
        var currentPreparedData = preparedData!!

        if (directSend) {
          currentDuplex.sendToServer(currentPreparedData)
          onReceived.accept(createHistoryResult())
          return
        }

        currentDuplex.execFastSend(currentPreparedData)
        if (isSync) {
          onReceived.accept(createHistoryResult())
          return
        }

        var data = currentDuplex.receive()!!

        /* 100 Continue 対策 */
        var encoder =
          EncoderManager.getInstance().createInstance(oneshot.getEncoder()!!, oneshot.getAlpn())
        if (
          encoder is EncodeHTTPBase && encoder.getHttpVersion() == EncodeHTTPBase.HTTPVersion.HTTP1
        ) {
          while (Http.create(data).statusCode == "100") {
            data = currentDuplex.receive()!!
          }
        }

        var result =
          OneShotPacket(
            oneshot.getId(),
            oneshot.getListenPort(),
            oneshot.getClient(),
            oneshot.getServer(),
            oneshot.getServerName()!!,
            oneshot.getUseSSL(),
            data,
            oneshot.getEncoder()!!,
            oneshot.getAlpn()!!,
            Packet.Direction.SERVER,
            oneshot.getConn(),
            oneshot.getGroup(),
          )
        onReceived.accept(result)
      }

      private fun createHistoryResult(): OneShotPacket =
        OneShotPacket(
          oneshot.getId(),
          oneshot.getListenPort(),
          oneshot.getClient(),
          oneshot.getServer(),
          oneshot.getServerName()!!,
          oneshot.getUseSSL(),
          I18nString.get(
              "In case that packets were resend to already connected socket, results can't be displayed in this window. See the history window instead."
            )
            .toByteArray(),
          oneshot.getEncoder()!!,
          oneshot.getAlpn()!!,
          Packet.Direction.SERVER,
          oneshot.getConn(),
          oneshot.getGroup(),
        )
    }
  }
}
