package packetproxy.common

import java.io.IOException
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLException
import javax.net.ssl.SSLProtocolException
import javax.net.ssl.StandardConstants

const val RECORD_HEADER_SIZE = 0x05

fun getRequiredSize(source: ByteBuffer): Int {
  val input = source.duplicate()
  if (input.remaining() < RECORD_HEADER_SIZE) throw BufferUnderflowException()
  val firstByte = input.get()
  val secondByte = input.get()
  val thirdByte = input.get()
  return if (firstByte.toInt() and 0x80 != 0 && thirdByte.toInt() == 0x01) {
    RECORD_HEADER_SIZE
  } else {
    ((input.get().toInt() and 0xff) shl 8 or (input.get().toInt() and 0xff)) + 5
  }
}

@Throws(IOException::class)
fun getRequiredSize(source: ByteArray, offset: Int, length: Int): Int =
  getRequiredSize(ByteBuffer.wrap(source, offset, length).asReadOnlyBuffer())

@Throws(IOException::class)
fun explore(source: ByteBuffer): SSLCapabilities {
  val input = source.duplicate()
  if (input.remaining() < RECORD_HEADER_SIZE) throw BufferUnderflowException()
  val firstByte = input.get()
  val secondByte = input.get()
  val thirdByte = input.get()
  return when {
    firstByte.toInt() and 0x80 != 0 && thirdByte.toInt() == 0x01 ->
      exploreV2HelloRecord(input, firstByte, secondByte, thirdByte)
    firstByte.toInt() == 22 -> exploreTLSRecord(input, firstByte, secondByte, thirdByte)
    else -> throw SSLException("Not handshake record")
  }
}

@Throws(IOException::class)
fun explore(source: ByteArray, offset: Int, length: Int): SSLCapabilities =
  explore(ByteBuffer.wrap(source, offset, length).asReadOnlyBuffer())

@Throws(IOException::class)
private fun exploreV2HelloRecord(
  input: ByteBuffer,
  firstByte: Byte,
  secondByte: Byte,
  thirdByte: Byte,
): SSLCapabilities =
  try {
    if (thirdByte.toInt() != 0x01) throw SSLException("Unsupported or Unrecognized SSL record")
    val helloVersionMajor = input.get()
    val helloVersionMinor = input.get()
    SSLCapabilitiesImpl(0x00, 0x02, helloVersionMajor, helloVersionMinor, emptyList())
  } catch (_: BufferUnderflowException) {
    throw SSLProtocolException("Invalid handshake record")
  }

@Throws(IOException::class)
private fun exploreTLSRecord(
  input: ByteBuffer,
  firstByte: Byte,
  secondByte: Byte,
  thirdByte: Byte,
): SSLCapabilities {
  if (firstByte.toInt() != 22) throw SSLException("Not handshake record")
  val recordLength = getInt16(input)
  if (recordLength > input.remaining()) throw BufferUnderflowException()
  return try {
    exploreHandshake(input, secondByte, thirdByte, recordLength)
  } catch (_: BufferUnderflowException) {
    throw SSLProtocolException("Invalid handshake record")
  }
}

@Throws(IOException::class)
private fun exploreHandshake(
  input: ByteBuffer,
  recordMajorVersion: Byte,
  recordMinorVersion: Byte,
  recordLength: Int,
): SSLCapabilities {
  if (input.get().toInt() != 0x01) throw IllegalStateException("Not initial handshaking")
  val handshakeLength = getInt24(input)
  if (handshakeLength > recordLength - 4) {
    throw SSLException("Handshake message spans multiple records")
  }
  val clientHello = input.duplicate()
  clientHello.limit(handshakeLength + clientHello.position())
  return exploreClientHello(clientHello, recordMajorVersion, recordMinorVersion)
}

@Throws(IOException::class)
private fun exploreClientHello(
  input: ByteBuffer,
  recordMajorVersion: Byte,
  recordMinorVersion: Byte,
): SSLCapabilities {
  val helloMajorVersion = input.get()
  val helloMinorVersion = input.get()
  input.position(input.position() + 32)
  ignoreByteVector8(input)
  ignoreByteVector16(input)
  ignoreByteVector8(input)
  val serverNames = if (input.remaining() > 0) exploreExtensions(input) else emptyList()
  return SSLCapabilitiesImpl(
    recordMajorVersion,
    recordMinorVersion,
    helloMajorVersion,
    helloMinorVersion,
    serverNames,
  )
}

@Throws(IOException::class)
private fun exploreExtensions(input: ByteBuffer): List<SNIServerName> {
  var length = getInt16(input)
  while (length > 0) {
    val extensionType = getInt16(input)
    val extensionLength = getInt16(input)
    if (extensionType == 0x00) return exploreSNIExt(input, extensionLength)
    ignoreByteVector(input, extensionLength)
    length -= extensionLength + 4
  }
  return emptyList()
}

@Throws(IOException::class)
private fun exploreSNIExt(input: ByteBuffer, extensionLength: Int): List<SNIServerName> {
  val serverNames = linkedMapOf<Int, SNIServerName>()
  var remaining = extensionLength
  if (extensionLength >= 2) {
    val listLength = getInt16(input)
    if (listLength == 0 || listLength + 2 != extensionLength) {
      throw SSLProtocolException("Invalid server name indication extension")
    }
    remaining -= 2
    while (remaining > 0) {
      val code = getInt8(input)
      val serverNameLength = getInt16(input)
      if (serverNameLength > remaining) {
        throw SSLProtocolException("Not enough data to fill declared vector size")
      }
      val encoded = ByteArray(serverNameLength)
      input.get(encoded)
      val serverName =
        if (code == StandardConstants.SNI_HOST_NAME) {
          if (encoded.isEmpty())
            throw SSLProtocolException("Empty HostName in server name indication")
          SNIHostName(encoded)
        } else {
          UnknownServerName(code, encoded)
        }
      if (serverNames.put(serverName.getType(), serverName) != null) {
        throw SSLProtocolException("Duplicated server name of type ${serverName.type}")
      }
      remaining -= encoded.size + 3
    }
  } else if (extensionLength == 0) {
    throw SSLProtocolException("Not server name indication extension in client")
  }
  if (remaining != 0) throw SSLProtocolException("Invalid server name indication extension")
  return serverNames.values.toList()
}

private fun getInt8(input: ByteBuffer): Int = input.get().toInt()

private fun getInt16(input: ByteBuffer): Int =
  ((input.get().toInt() and 0xff) shl 8) or (input.get().toInt() and 0xff)

private fun getInt24(input: ByteBuffer): Int =
  ((input.get().toInt() and 0xff) shl 16) or
    ((input.get().toInt() and 0xff) shl 8) or
    (input.get().toInt() and 0xff)

private fun ignoreByteVector8(input: ByteBuffer) = ignoreByteVector(input, getInt8(input))

private fun ignoreByteVector16(input: ByteBuffer) = ignoreByteVector(input, getInt16(input))

private fun ignoreByteVector(input: ByteBuffer, length: Int) {
  if (length != 0) input.position(input.position() + length)
}

private class UnknownServerName(code: Int, encoded: ByteArray) : SNIServerName(code, encoded)

private class SSLCapabilitiesImpl(
  recordMajorVersion: Byte,
  recordMinorVersion: Byte,
  helloMajorVersion: Byte,
  helloMinorVersion: Byte,
  private val sniNames: List<SNIServerName>,
) : SSLCapabilities() {
  private val recordVersion = versionName(recordMajorVersion, recordMinorVersion)
  private val helloVersion = versionName(helloMajorVersion, helloMinorVersion)

  override fun getRecordVersion(): String = recordVersion

  override fun getHelloVersion(): String = helloVersion

  override fun getServerNames(): List<SNIServerName> = sniNames

  private fun versionName(major: Byte, minor: Byte): String {
    val version = (major.toInt() shl 8) or minor.toInt()
    return versions[version] ?: "Unknown-${major.toInt()}.${minor.toInt()}"
  }
}

private val versions =
  mapOf(
    0x0002 to "SSLv2Hello",
    0x0300 to "SSLv3",
    0x0301 to "TLSv1",
    0x0302 to "TLSv1.1",
    0x0303 to "TLSv1.2",
  )
