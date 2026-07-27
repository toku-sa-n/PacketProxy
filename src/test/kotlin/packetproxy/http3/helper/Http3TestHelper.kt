package packetproxy.http3.helper

import org.eclipse.jetty.http.HttpFields
import org.eclipse.jetty.http.HttpURI
import org.eclipse.jetty.http.HttpVersion
import org.eclipse.jetty.http.MetaData
import packetproxy.http.Http

object Http3TestHelper {
  @JvmStatic
  @Throws(Exception::class)
  fun generateTestMetaData(): MetaData {
    val http =
      Http.create(
        "POST / HTTP/3\nhost: example.com\nhoge: fuga\ncontent-type: application/json\n\n{\"name\":\"taro\",\"age\":20}"
          .toByteArray()
      )
    val fields = HttpFields.build()
    http.header.fields.forEach { fields.add(it.getName(), it.getValue()) }
    return MetaData.Request(
      http.method,
      HttpURI.from(http.getURL(80, false)),
      HttpVersion.HTTP_3,
      fields,
    )
  }
}
