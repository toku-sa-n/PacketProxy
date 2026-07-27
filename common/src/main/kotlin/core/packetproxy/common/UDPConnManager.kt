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

import java.net.DatagramPacket
import java.net.InetSocketAddress
import java.util.concurrent.BlockingQueue
import java.util.concurrent.LinkedBlockingQueue

class UDPConnManager {
  private val connList = mutableMapOf<InetSocketAddress, UDPConn>()
  private val acceptedQueue: BlockingQueue<InetSocketAddress> = LinkedBlockingQueue()
  private val recvQueue: BlockingQueue<DatagramPacket> = LinkedBlockingQueue()

  fun accept(): Endpoint {
    val addr = acceptedQueue.take()
    return connList[addr]!!.getEndpoint()
  }

  fun put(packet: DatagramPacket) {
    val addr = InetSocketAddress(packet.address, packet.getPort())
    var conn = query(addr)
    if (conn == null) {
      conn = create(addr)
      conn.getAutomatically(recvQueue)
      acceptedQueue.put(addr)
    }
    conn.put(packet.getData(), 0, packet.length)
  }

  fun get(): DatagramPacket = recvQueue.take()

  private fun query(key: InetSocketAddress): UDPConn? = connList[key]

  private fun create(key: InetSocketAddress): UDPConn {
    val conn = UDPConn(key)
    connList[key] = conn
    return conn
  }
}
