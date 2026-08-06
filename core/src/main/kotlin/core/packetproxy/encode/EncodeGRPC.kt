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
package packetproxy.encode

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.Arrays
import org.apache.commons.lang3.ArrayUtils
import packetproxy.common.Protobuf3
import packetproxy.common.UniqueID
import packetproxy.common.Utils
import packetproxy.grpc.GrpcSchemaResolver
import packetproxy.grpc.GrpcServiceRegistryStore
import packetproxy.http.Http
import packetproxy.http2.Grpc

open class EncodeGRPC : EncodeHTTPBase {
  private val schemaResolver = GrpcSchemaResolver(GrpcServiceRegistryStore())

  private var compressedFlag: Byte = 0
  @Volatile private var lastGrpcPath: String? = null

  @Throws(Exception::class) constructor() : super()

  @Throws(Exception::class) constructor(ALPN: String?) : super(ALPN, Grpc(UniqueID()))

  override fun getName(): String = "gRPC"

  @Throws(Exception::class)
  override fun decodeClientRequestHttp(inputHttp: Http): Http {
    lastGrpcPath = inputHttp.path
    val reg = schemaResolver.resolveRegistryForRequest(inputHttp)
    val type = reg?.getInputType(lastGrpcPath)
    if (type != null) {
      inputHttp.body = schemaResolver.decodeSchemaAwareBody(inputHttp.body, type)
      return inputHttp
    }
    val raw = inputHttp.body
    val body = ByteArrayOutputStream()
    var pos = 0
    while (pos < raw.size) {
      compressedFlag = raw[pos]
      if (compressedFlag.toInt() != 0) {
        throw Exception("gRPC: compressed flag in gRPC message is not supported yet")
      }
      pos += 1
      if (pos + 4 > raw.size) {
        throw Exception("gRPC: truncated message length")
      }
      val messageLength = ByteBuffer.wrap(Arrays.copyOfRange(raw, pos, pos + 4)).getInt()
      pos += 4
      if (messageLength < 0 || pos + messageLength > raw.size) {
        throw Exception("gRPC: invalid message length $messageLength")
      }
      val grpcMsg = Arrays.copyOfRange(raw, pos, pos + messageLength)
      val decodedMsg = decodeGrpcClientPayload(grpcMsg)
      if (body.size() > 0) {
        body.write("\n".toByteArray())
      }
      body.write(Protobuf3.decode(decodedMsg).toByteArray(StandardCharsets.UTF_8))
      pos += messageLength
    }
    inputHttp.body = body.toByteArray()
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeClientRequestHttp(inputHttp: Http): Http {
    lastGrpcPath = inputHttp.path
    val reg = schemaResolver.resolveRegistryForRequest(inputHttp)
    val type = reg?.getInputType(lastGrpcPath)
    if (type != null) {
      inputHttp.body = schemaResolver.encodeSchemaAwareBody(inputHttp.body, type)
      return inputHttp
    }
    val body = inputHttp.body
    val rawStream = ByteArrayOutputStream()
    var pos = 0
    while (pos < body.size) {
      val subBody: ByteArray
      val idx = Utils.indexOf(body, pos, body.size, "\n}".toByteArray())
      if (idx > 0) { // split into gRPC messages
        subBody = ArrayUtils.subarray(body, pos, idx + 2)
        pos = idx + 2
      } else {
        subBody = ArrayUtils.subarray(body, pos, body.size)
        pos = body.size
      }
      val msg = String(subBody, StandardCharsets.UTF_8)
      val data = Protobuf3.encode(msg)
      val encodedData = encodeGrpcClientPayload(data)
      val encodedDataLen = encodedData.size
      rawStream.write(0) // always compressed flag is zero
      rawStream.write(ByteBuffer.allocate(4).putInt(encodedDataLen).array())
      rawStream.write(encodedData)
    }
    inputHttp.body = rawStream.toByteArray()
    return inputHttp
  }

  @Throws(Exception::class)
  override fun decodeServerResponseHttp(inputHttp: Http): Http {
    val raw = inputHttp.body
    if (raw.isEmpty()) {
      return inputHttp
    }
    val reg = schemaResolver.effectiveRegistry(inputHttp)
    val type = reg?.getOutputType(lastGrpcPath)
    if (type != null) {
      inputHttp.body = schemaResolver.decodeSchemaAwareBody(raw, type)
      return inputHttp
    }
    val body = ByteArrayOutputStream()
    var pos = 0
    while (pos < raw.size) {
      compressedFlag = raw[pos]
      if (compressedFlag.toInt() != 0) {
        throw Exception("gRPC: compressed flag in gRPC message is not supported yet")
      }
      pos += 1
      if (pos + 4 > raw.size) {
        throw Exception("gRPC: truncated message length")
      }
      val messageLength = ByteBuffer.wrap(Arrays.copyOfRange(raw, pos, pos + 4)).getInt()
      pos += 4
      if (messageLength < 0 || pos + messageLength > raw.size) {
        throw Exception("gRPC: invalid message length $messageLength")
      }
      val grpcMsg = Arrays.copyOfRange(raw, pos, pos + messageLength)
      val decodedMsg = decodeGrpcServerPayload(grpcMsg)
      if (body.size() > 0) {
        body.write("\n".toByteArray())
      }
      body.write(Protobuf3.decode(decodedMsg).toByteArray(StandardCharsets.UTF_8))
      pos += messageLength
    }
    inputHttp.body = body.toByteArray()
    return inputHttp
  }

  @Throws(Exception::class)
  override fun encodeServerResponseHttp(inputHttp: Http): Http {
    val body = inputHttp.body
    if (body.isEmpty()) {
      return inputHttp
    }
    val reg = schemaResolver.effectiveRegistry(inputHttp)
    val type = reg?.getOutputType(lastGrpcPath)
    if (type != null) {
      inputHttp.body = schemaResolver.encodeSchemaAwareBody(body, type)
      return inputHttp
    }
    val rawStream = ByteArrayOutputStream()
    var pos = 0
    while (pos < body.size) {
      val subBody: ByteArray
      val idx = Utils.indexOf(body, pos, body.size, "\n}".toByteArray())
      if (idx > 0) { // split into gRPC messages
        subBody = ArrayUtils.subarray(body, pos, idx + 2)
        pos = idx + 2
      } else {
        subBody = ArrayUtils.subarray(body, pos, body.size)
        pos = body.size
      }
      val msg = String(subBody, StandardCharsets.UTF_8)
      val data = Protobuf3.encode(msg)
      val encodedData = encodeGrpcServerPayload(data)
      val encodedDataLen = encodedData.size
      rawStream.write(0) // always compressed flag is zero
      rawStream.write(ByteBuffer.allocate(4).putInt(encodedDataLen).array())
      rawStream.write(encodedData)
    }
    inputHttp.body = rawStream.toByteArray()
    return inputHttp
  }

  @Throws(Exception::class)
  open fun decodeGrpcClientPayload(payload: ByteArray): ByteArray = payload

  @Throws(Exception::class)
  open fun encodeGrpcClientPayload(payload: ByteArray): ByteArray = payload

  @Throws(Exception::class)
  open fun decodeGrpcServerPayload(payload: ByteArray): ByteArray = payload

  @Throws(Exception::class)
  open fun encodeGrpcServerPayload(payload: ByteArray): ByteArray = payload
}
