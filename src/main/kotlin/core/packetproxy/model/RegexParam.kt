package packetproxy.model

import com.google.re2j.Pattern
import java.nio.charset.Charset
import packetproxy.util.CharSetUtility

class RegexParam(private var packetId: Int, private var name: String, regex: String) {
  private var regex: Pattern = Pattern.compile(regex)
  private var value: String = ""

  fun getPacketId(): Int = this.packetId

  fun getName(): String = this.name

  fun getRegex(): String = this.regex.pattern()

  fun getValue(): String = this.value

  fun setValue(value: String) {
    this.value = value
  }

  fun setValue(oneshot: OneShotPacket) {
    val dataByte = oneshot.getData()
    val charSetUtility = CharSetUtility.getInstance()
    var encoding = charSetUtility.guessCharSetFromHttpHeader(dataByte)
    if (encoding == "") {
      encoding = charSetUtility.guessCharSetFromMetatag(dataByte)
    }
    if (encoding == "") {
      encoding = "utf-8"
    }

    val data = String(dataByte, Charset.forName(encoding))
    val matcher = this.regex.matcher(data)
    if (matcher.find()) {
      this.value = matcher.group(1)
    }
  }

  @Throws(Exception::class)
  fun applyToPacket(oneshot: OneShotPacket): OneShotPacket {
    var data = oneshot.getData()
    val charSetUtility = CharSetUtility.getInstance()
    var encoding = charSetUtility.guessCharSetFromHttpHeader(data)
    if (encoding == "") {
      charSetUtility.guessCharSetFromMetatag(data)
    }
    if (encoding == "") {
      encoding = "utf-8"
    }

    var dataStr = String(data, Charset.forName(encoding))
    val pat = Pattern.compile("\\$\\{${this.name}\\}\\$")
    val matcher = pat.matcher(dataStr)
    if (matcher.find()) {
      dataStr = matcher.replaceAll(this.value)
    }

    data = dataStr.toByteArray(charset(encoding))
    oneshot.setData(data)

    return oneshot
  }
}
