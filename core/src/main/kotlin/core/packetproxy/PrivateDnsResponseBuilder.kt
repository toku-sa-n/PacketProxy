/*
 * Copyright (c) 1998-2011, Brian Wellington.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package packetproxy

import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import org.xbill.DNS.AAAARecord
import org.xbill.DNS.ARecord
import org.xbill.DNS.ExtendedFlags
import org.xbill.DNS.Flags
import org.xbill.DNS.Header
import org.xbill.DNS.Message
import org.xbill.DNS.OPTRecord
import org.xbill.DNS.Opcode
import org.xbill.DNS.Rcode
import org.xbill.DNS.Record
import org.xbill.DNS.Section
import org.xbill.DNS.Type

class PrivateDnsResponseBuilder {
  private val spoofIP: String?
  private val answer: Record?
  private val answers: Array<Record>?

  constructor() : this(null, null, null)

  constructor(ip: String?) : this(ip, null, null)

  constructor(answer: Record?) : this(null, answer, null)

  constructor(answers: Array<Record>?) : this(null, null, answers)

  private constructor(spoofIP: String?, answer: Record?, answers: Array<Record>?) {
    this.spoofIP = spoofIP
    this.answer = answer
    this.answers = answers
  }

  @Throws(IOException::class)
  fun generateReply(query: Message, `in`: ByteArray, length: Int, s: Socket?): ByteArray? {
    val header = query.getHeader()
    if (header.getFlag(Flags.QR.toInt())) {
      return null
    }
    if (header.getRcode() != Rcode.NOERROR) {
      return errorMessage(query, Rcode.FORMERR)
    }
    if (header.getOpcode() != Opcode.QUERY) {
      return errorMessage(query, Rcode.NOTIMP)
    }

    val queryRecord = query.getQuestion()
    val queryOpt = query.getOPT()
    val response = Message(header.getID())
    response.getHeader().setFlag(Flags.QR.toInt())
    if (header.getFlag(Flags.RD.toInt())) {
      response.getHeader().setFlag(Flags.RD.toInt())
    }
    response.addRecord(queryRecord, Section.QUESTION)

    if (answer != null) {
      response.addRecord(answer, Section.ANSWER)
    }
    if (answers != null) {
      for (record in answers) {
        response.addRecord(record, Section.ANSWER)
      }
    }
    if (spoofIP != null) {
      response.addRecord(createSpoofedRecord(queryRecord), Section.ANSWER)
    }

    val maxLength = getMaxLength(queryOpt, s)
    addOptRecord(response, queryOpt)
    return response.toWire(maxLength)
  }

  @Throws(IOException::class)
  private fun createSpoofedRecord(queryRecord: Record): Record {
    val name = queryRecord.getName()
    val dclass = queryRecord.getDClass()
    val address = InetAddress.getByName(spoofIP)
    if (queryRecord.getType() == Type.A) {
      return ARecord(name, dclass, 0, address)
    }
    return AAAARecord(name, dclass, 0, address)
  }

  private fun getMaxLength(queryOpt: OPTRecord?, s: Socket?): Int {
    if (s != null) {
      return 65535
    }
    if (queryOpt != null) {
      return maxOf(queryOpt.getPayloadSize(), 512)
    }
    return 512
  }

  private fun addOptRecord(response: Message, queryOpt: OPTRecord?) {
    if (queryOpt == null) {
      return
    }
    val optFlags = if ((queryOpt.getFlags() and ExtendedFlags.DO) != 0) ExtendedFlags.DO else 0
    response.addRecord(OPTRecord(4096, Rcode.NOERROR, 0, optFlags), Section.ADDITIONAL)
  }

  fun notImplementedReply(query: Message): ByteArray = errorMessage(query, Rcode.NOTIMP)

  private fun errorMessage(query: Message, rcode: Int): ByteArray =
    buildErrorMessage(query.getHeader(), rcode, query.getQuestion())

  private fun buildErrorMessage(header: Header, rcode: Int, question: Record?): ByteArray {
    val response = Message()
    response.setHeader(header)
    var i = Section.QUESTION
    while (i <= Section.ADDITIONAL) {
      response.removeAllRecords(i)
      i++
    }
    if (rcode == Rcode.SERVFAIL && question != null) {
      response.addRecord(question, Section.QUESTION)
    }
    header.setRcode(rcode)
    return response.toWire()
  }
}
