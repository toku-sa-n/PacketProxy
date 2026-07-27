package packetproxy.extensions.samplehttp.encoder

import packetproxy.encode.EncodeHTTPBase
import packetproxy.http.Http

class SampleHTTP @Throws(Exception::class) constructor(ALPN: String?) : EncodeHTTPBase(ALPN) {

  override fun getName(): String = "SampleHTTP from extension"

  @Throws(Exception::class) override fun decodeClientRequestHttp(inputHttp: Http): Http = inputHttp

  @Throws(Exception::class) override fun encodeClientRequestHttp(inputHttp: Http): Http = inputHttp

  @Throws(Exception::class) override fun decodeServerResponseHttp(inputHttp: Http): Http = inputHttp

  @Throws(Exception::class) override fun encodeServerResponseHttp(inputHttp: Http): Http = inputHttp
}
