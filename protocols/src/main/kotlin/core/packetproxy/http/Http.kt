/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package packetproxy.http

import com.google.re2j.Pattern
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.URL
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Arrays
import java.util.Optional
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import org.apache.commons.collections4.map.MultiValueMap
import org.apache.commons.compress.compressors.brotli.BrotliCompressorInputStream
import org.apache.commons.compress.compressors.zstandard.ZstdCompressorInputStream
import org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream
import org.apache.commons.io.IOUtils
import org.apache.commons.lang3.ArrayUtils
import packetproxy.PrivateDNSClient
import packetproxy.common.Parameter
import packetproxy.common.Utils
import packetproxy.model.Resolutions
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class Http
private constructor(
  data: ByteArray,
  withoutTouchingContentLength: Boolean,
  private val resolutions: Resolutions?,
) {
  @JvmField var header: HttpHeader
  private var originalHeader: HttpHeader
  private var rawBody: ByteArray
  @JvmField var statusCode: String = ""
  @JvmField var method: String = ""
  private var proxyHost: String? = null
  private var proxyPort = 0
  @JvmField var path: String = ""
  private var queryString: QueryString
  private var version: String? = null
  @JvmField var body: ByteArray
  private var flag_request = false
  private var flag_proxy = false
  private var flag_proxy_ssl = false
  private var flag_disable_proxy_format_url = false
  private var flag_disable_content_length = false
  private var flag_dont_touch_content_length = false

  init {
    if (withoutTouchingContentLength) {
      dontTouchContentLength()
    }
    queryString = QueryString("")
    header = HttpHeader(data)
    originalHeader = HttpHeader(data)
    analyzeStatusLine(header.getStatusline())
    rawBody = getHttpBody(data)
    body = getCookedBody(header, rawBody)
  }

  fun getHeader(): HttpHeader = header

  val serverName: String
    get() = proxyHost ?: ""

  val serverAddr: InetSocketAddress
    @Throws(Exception::class)
    get() =
      InetSocketAddress(
        PrivateDNSClient()
          .getByName(
            serverName,
            requireNotNull(resolutions) {
              "Resolutions is required to resolve the HTTP server address"
            },
          ),
        proxyPort,
      )

  fun getServerPort(): Int = proxyPort

  val isProxy: Boolean
    get() = flag_proxy

  val isProxySsl: Boolean
    get() = flag_proxy_ssl

  fun getBody(): ByteArray = body

  fun setPath(path: String?) {
    this.path = path ?: ""
  }

  fun getPath(): String = this.path

  fun getMethod(): String = this.method

  val host: String?
    get() = header.getValue("Host").orElse(null)

  fun setQuery(query: String) {
    this.queryString = QueryString(query)
  }

  fun setQuery(query: QueryString) {
    this.queryString = query
  }

  fun getQuery(): QueryString = this.queryString

  fun getQueryAsString(): String = this.queryString.toString()

  fun getStatusCode(): String = this.statusCode

  fun setBody(body: ByteArray?) {
    this.body = body ?: byteArrayOf()
  }

  fun disableContentLength() {
    this.flag_disable_content_length = true
  }

  /* Content-Lengthには触らない */
  /* HEADのレスポンス等で利用 */
  fun dontTouchContentLength() {
    this.flag_dont_touch_content_length = true
  }

  fun disableProxyFormatUrl() {
    this.flag_disable_proxy_format_url = true
  }

  fun getURL(port: Int, use_ssl: Boolean): String {
    if (version == "HTTP/2" || version == "HTTP/3") {
      return getURI(use_ssl)
    } else {
      /* HTTP/1.1 */
      var query =
        if (getQueryAsString().isNotEmpty()) {
          "?" + getQueryAsString()
        } else {
          ""
        }
      var path = getPath()
      var host = header.getValue("Host").orElse(null)
      var protocol = if (use_ssl) "https" else "http"
      return String.format("%s://%s%s%s", protocol, host, path, query)
    }
  }

  @Throws(Exception::class)
  fun toByteArray(): ByteArray {
    var result = byteArrayOf()
    var newLine = "\r\n".toByteArray()
    var statusLine = header.getStatusline()

    if (flag_request) {
      var query =
        if (getQueryAsString().isNotEmpty()) {
          "?" + getQueryAsString()
        } else {
          ""
        }
      if (this.isProxy && !this.flag_disable_proxy_format_url) {
        var proxyPort = if (getServerPort() > 0) ":" + getServerPort().toString() else ""
        statusLine =
          String.format(
            "%s http://%s%s%s%s %s",
            this.method,
            serverName,
            proxyPort,
            getPath(),
            query,
            this.version,
          )
      } else {
        statusLine = String.format("%s %s%s %s", this.method, this.getPath(), query, this.version)
      }
    }

    result += statusLine.toByteArray()
    result += newLine
    if (!flag_request && this.statusCode == "100") {
      // 100 Continueの場合は、Content-Lengthがいらないのですぐに返す
      result += newLine
      return result
    }
    result += header.toByteArray()

    if (
      body.isEmpty() &&
        flag_request &&
        this.host != null &&
        (this.host == "dpoint.jp" ||
          this.host == "id.smt.docomo.ne.jp" ||
          this.host == "cfg.smt.docomo.ne.jp")
    ) {
      // 特定サイトでは Content-Length: 0をつけるとうまく動かないので例外処理する
    } else if (this.flag_disable_content_length) {
      // content-lengthがいらないと明示的に指定したケース
    } else if (this.flag_dont_touch_content_length) {
      // content-lengthを触らないと明示的に指定したケース
    } else {
      // Content-Typeがないパターンでも必ずContent-Lengthはつけるべき
      result += String.format("Content-Length: %d", body.size).toByteArray()
      result += newLine
    }

    result += newLine
    return result + body
  }

  fun getOriginalHeader(): HttpHeader = originalHeader

  fun isGzipEncoded(): Boolean =
    getOriginalHeader().getValue("Content-Encoding").orElse("").equals("gzip", ignoreCase = true)

  @Throws(Exception::class)
  fun encodeBodyByGzip() {
    body = gzip(body)
    header.update("Content-Encoding", "gzip")
  }

  fun getBodyParamsOrder(): List<String>? {
    var body: String
    try {
      body = String(getBody(), StandardCharsets.UTF_8)
    } catch (e: Exception) {
      errWithStackTrace(e)
      return null
    }
    var pairs = body.split("&")
    var usedName = HashSet<String>()
    var names = pairs.map { it.split("=")[0] }

    return names.filter { n -> !usedName.contains(n) }.onEach { usedName.add(it) }
  }

  fun getBodyParams(): MultiValueMap<String, Parameter>? {
    var body: String
    try {
      body = String(getBody(), StandardCharsets.UTF_8)
    } catch (e: Exception) {
      errWithStackTrace(e)
      return null
    }
    var pairs = body.split("&")
    var nameToParams = MultiValueMap<String, Parameter>()
    for (param in pairs) {
      var p = Parameter(param)
      nameToParams.put(p.getName(), p)
    }
    return nameToParams
  }

  fun setBodyParams(params: List<Parameter>) {
    var paramStrings = params.map { it.toString() }
    setBody(paramStrings.joinToString("&").toByteArray())
  }

  fun getCookie(key: String): String? {
    var cookies = getHeader().getAllValue("Cookie")
    var cookieMap =
      cookies
        .flatMap { v -> v.split(";\\s*".toRegex()) }
        .map { kv -> kv.split("=") }
        .associate { kv ->
          URLDecoder.decode(kv[0], StandardCharsets.UTF_8) to
            URLDecoder.decode(kv[1], StandardCharsets.UTF_8)
        }
    return cookieMap[key]
  }

  fun getOverrideHttpMethod(): String {
    var tmp = this.getFirstHeader("X-HTTP-Method-Override")
    return if (tmp.isEmpty()) this.method else tmp
  }

  // 以下非推奨 互換性のため
  fun getFirstHeader(key: String): String = header.getValue(key).orElse("")

  fun removeHeader(key: String) {
    header.removeAll(key)
  }

  fun updateHeader(key: String, value: String) {
    header.update(key, value)
  }

  fun removeMatches(regex: String) {
    header.removeMatches(regex)
  }

  fun getHeader(key: String): List<String> = header.getAllValue(key)

  val isRequest: Boolean
    get() = flag_request

  @Throws(Exception::class)
  private fun getCookedBody(header: HttpHeader, rawBody: ByteArray): ByteArray {
    var cookedBody = rawBody

    run {
      var headerName = "Transfer-Encoding"
      var enc: Optional<String> = header.getValue(headerName)

      if (enc.isPresent && enc.get().equals("chunked", ignoreCase = true)) {
        header.removeAll(headerName)
        cookedBody = getChankedHttpBodyFussy(cookedBody)
      }
    }

    run {
      var headerName = "Content-Encoding"
      var enc: Optional<String> = header.getValue(headerName)

      if (enc.isPresent && enc.get().equals("gzip", ignoreCase = true)) {
        cookedBody = gunzip(cookedBody)
        header.removeAll(headerName)
      } else if (enc.isPresent && enc.get().equals("zstd", ignoreCase = true)) {
        cookedBody = zstd_decompress(cookedBody)
        header.removeAll(headerName)
      } else if (enc.isPresent && enc.get().equals("br", ignoreCase = true)) {
        cookedBody = br_decompress(cookedBody)
        header.removeAll(headerName)
      }
    }

    if (!this.flag_dont_touch_content_length) {
      header.removeAll("Content-Length")
    }
    return cookedBody
  }

  private fun getURI(use_ssl: Boolean): String {
    var authority = "unknown"
    if (version == "HTTP/2") {
      authority = getFirstHeader("X-PacketProxy-HTTP2-Host")
    } else if (version == "HTTP/3") {
      authority = getFirstHeader("x-packetproxy-http3-host")
    }
    var scheme = if (use_ssl) "https" else "http"
    var path = getPath()
    var query = getQueryAsString()
    var queryStr = if (query.isNotEmpty()) "?$query" else ""
    return "$scheme://$authority$path$queryStr"
  }

  @Throws(Exception::class)
  private fun analyzeRequestStatusLine(status_line: String) {
    var matcher = STATUS_LINE_PATTERN.matcher(status_line)
    if (matcher.find()) {
      this.method = matcher.group(1).trim()
      this.version = matcher.group(3).trim()
      if (this.method.startsWith("CONNECT")) {
        var urlStr = matcher.group(2).trim()
        var url = URL("https://$urlStr/")
        this.proxyHost = url.host
        this.proxyPort = if (url.getPort() > 0) url.port else 443
        if (this.proxyPort == 80) {
          // websocketとかは平文だけどCONNECTが来る事があるので80番ポートは平文と決め打ち
          flag_proxy = true
        } else if (this.proxyPort == 443) {
          flag_proxy_ssl = true
        } else {
          // 多分httpsだけど、httpだと原因を探すのが大変になるので一応エラー出力しておく
          flag_proxy_ssl = true
          log("%s can't distinguish HTTP or HTTPS, but use HTTPS", status_line)
        }
      } else {
        var urlStr = matcher.group(2).trim()
        if (urlStr.startsWith("http")) {
          flag_proxy = true
          var url = URL(urlStr)
          this.proxyHost = url.host
          this.proxyPort = if (url.getPort() > 0) url.port else 80
          this.path = url.path
          if (url.query != null) {
            this.queryString = QueryString(url.query)
          }
        } else {
          /* normal */
          var url = URL("http://example.com$urlStr")
          this.path = url.path
          if (url.query != null) {
            this.queryString = QueryString(url.query)
          }
        }
      }
    }
  }

  @Throws(Exception::class)
  private fun replaceStatusLineToNonProxyStyte(status_line: String): String {
    var result = status_line
    var matcher = HTTP_URL_PATTERN.matcher(status_line)
    if (matcher.find()) {
      result = matcher.replaceAll("")
    }
    return result
  }

  @Throws(Exception::class)
  private fun analyzeResponseStatusLine(status_line: String) {
    var matcher = STATUS_LINE_PATTERN2.matcher(status_line)
    if (matcher.find()) {
      this.statusCode = matcher.group(1).trim()
    }
  }

  @Throws(Exception::class)
  private fun analyzeStatusLine(status_line: String) {
    var matcher = STATUS_LINE_PATTERN3.matcher(status_line)
    if (matcher.find()) {
      if (matcher.group(1).trim().startsWith("HTTP")) {
        analyzeResponseStatusLine(status_line)
      } else {
        flag_request = true
        analyzeRequestStatusLine(status_line)
      }
    }
  }

  companion object {
    val CONTINUE_PATTERN: Pattern =
      Pattern.compile("HTTP/1.1 100 Continue\r?\n\r?\n", Pattern.CASE_INSENSITIVE)
    val PLAIN_PATTERN: Pattern =
      Pattern.compile("\nContent-Length *: *([0-9]+)", Pattern.CASE_INSENSITIVE)
    val CHUNKED_PATTERN: Pattern =
      Pattern.compile("\nTransfer-Encoding *: *chunked", Pattern.CASE_INSENSITIVE)
    val GZIP_PATTERN: Pattern =
      Pattern.compile("\nContent-Encoding *: *gzip", Pattern.CASE_INSENSITIVE)
    val ZSTD_PATTERN: Pattern =
      Pattern.compile("\nContent-Encoding *: *zstd", Pattern.CASE_INSENSITIVE)
    val BR_PATTERN: Pattern = Pattern.compile("\nContent-Encoding *: *br", Pattern.CASE_INSENSITIVE)
    val STATUS_LINE_PATTERN: Pattern = Pattern.compile("([^ ]+) +([^ ]+) +([^ ]+)$")
    val HTTP_URL_PATTERN: Pattern = Pattern.compile("http://[^/]+")
    val STATUS_LINE_PATTERN2: Pattern = Pattern.compile("[^ ]+ +([^ ]+) +([a-z0-9A-Z ]+)$")
    val STATUS_LINE_PATTERN3: Pattern = Pattern.compile("^([^ ]+)")

    @JvmStatic @Throws(Exception::class) fun create(data: ByteArray): Http = Http(data, false, null)

    @JvmStatic
    @Throws(Exception::class)
    fun create(data: ByteArray, resolutions: Resolutions): Http = Http(data, false, resolutions)

    @JvmStatic
    @Throws(Exception::class)
    fun createWithoutTouchingContentLength(data: ByteArray): Http = Http(data, true, null)

    @JvmStatic
    @Throws(Exception::class)
    fun createWithoutTouchingContentLength(data: ByteArray, resolutions: Resolutions): Http =
      Http(data, true, resolutions)

    // TODO header系作業をHttpHeaderに分離
    @JvmStatic
    @Throws(Exception::class)
    fun parseHttpDelimiter(data: ByteArray): Int {
      var header_size = HttpHeader.calcHeaderSize(data)
      if (header_size == -1) {
        return -1
      }

      var header = ArrayUtils.subarray(data, 0, header_size)
      var header_str = String(header, StandardCharsets.UTF_8)

      var continue_matcher = CONTINUE_PATTERN.matcher(header_str)
      if (continue_matcher.find()) {
        header_size = continue_matcher.end()
        return header_size
      }

      var plain_matcher = PLAIN_PATTERN.matcher(header_str)
      var content_length: Int
      if (plain_matcher.find()) {
        content_length = plain_matcher.group(1).toInt()
      } else {
        content_length = 0
      }

      var matcher = CHUNKED_PATTERN.matcher(header_str)
      if (matcher.find()) {
        var body = ArrayUtils.subarray(data, header_size, data.size)
        var finishFlag = "0\r\n\r\n".toByteArray()
        if (body.size < finishFlag.size) {
          return -1
        }
        if (
          Arrays.compare(
            finishFlag,
            0,
            finishFlag.size,
            body,
            body.size - finishFlag.size,
            body.size,
          ) != 0
        ) {
          return -1
        }
        body = getChankedHttpBody(body)
        if (body == null) return -1
      }

      if (content_length == 0) {
        return data.size
      }

      if (data.size < header_size + content_length) {
        return -1
      }
      return header_size + content_length
    }

    @JvmStatic fun isHTTP(data: ByteArray): Boolean = HttpHeader.isHTTPHeader(data)

    @Throws(Exception::class)
    private fun getHttpBody(input_data: ByteArray): ByteArray {
      var search_words =
        arrayOf("\r\n\r\n".toByteArray(), "\n\n".toByteArray(), "\r\r".toByteArray())
      for (search_word in search_words) {
        var idx = Utils.indexOf(input_data, 0, input_data.size, search_word)
        if (idx < 0) {
          continue
        }
        return ArrayUtils.subarray(input_data, idx + search_word.size, input_data.size)
      }
      return byteArrayOf()
    }

    @Throws(Exception::class)
    private fun zstd_decompress(input_data: ByteArray): ByteArray {
      var `in` = ByteArrayInputStream(input_data)
      var zstdIn = ZstdCompressorInputStream(`in`)
      return IOUtils.toByteArray(zstdIn)
    }

    @Throws(Exception::class)
    private fun zstd_compress(input_data: ByteArray): ByteArray {
      var out = ByteArrayOutputStream()
      var zstdOut = ZstdCompressorOutputStream(out)
      zstdOut.write(input_data)
      return out.toByteArray()
    }

    @Throws(Exception::class)
    private fun br_decompress(input_data: ByteArray): ByteArray {
      var `in` = ByteArrayInputStream(input_data)
      var brIn = BrotliCompressorInputStream(`in`)
      return IOUtils.toByteArray(brIn)
    }

    @Throws(Exception::class)
    private fun gunzip(input_data: ByteArray): ByteArray {
      if (input_data.isEmpty()) {
        return input_data
      }
      try {
        var `in` = ByteArrayInputStream(input_data)
        var gzin = GZIPInputStream(`in`)
        return IOUtils.toByteArray(gzin)
      } catch (e: Exception) {
        /* Streaming Responseサポートのため、中途半端なgzipを展開しないといけないケースが多々ある */
        var zipped = input_data
        var `in`: InputStream = GZIPInputStream(ByteArrayInputStream(zipped))
        var inflates = ByteArray(zipped.size * 10)
        var inflatesLength: Int
        var unzipped = ByteArrayOutputStream()
        try {
          while (`in`.read(inflates, 0, inflates.size).also { inflatesLength = it } > 0) {
            unzipped.write(ArrayUtils.subarray(inflates, 0, inflatesLength))
          }
        } catch (e1: Exception) {}
        return unzipped.toByteArray()
      }
    }

    @Throws(Exception::class)
    private fun gzip(input_data: ByteArray): ByteArray {
      var out = ByteArrayOutputStream()
      var gout = GZIPOutputStream(out)
      gout.write(input_data)
      gout.close()
      return out.toByteArray()
    }

    @Throws(Exception::class)
    private fun getChankedHttpBodyFussy(input_data: ByteArray): ByteArray {
      // TODO 改行コードの対応
      var search_word = "\r\n".toByteArray()
      var index: Int
      var start_index = 0
      var body = byteArrayOf()
      while (
        Utils.indexOf(input_data, start_index, input_data.size, search_word).also { index = it } >=
          0
      ) {
        try {
          var chank_header = ArrayUtils.subarray(input_data, start_index, index)
          var chank_length_str =
            String(chank_header, StandardCharsets.UTF_8).replace(Regex("^0+([^0].*)$"), "$1")
          var chank_length = chank_length_str.trim().toInt(16)
          if (chank_length == 0) {
            return body
          }
          var chank =
            ArrayUtils.subarray(
              input_data,
              index + search_word.size,
              index + search_word.size + chank_length,
            )
          body += chank
          start_index = index + search_word.size * 2 + chank_length
        } catch (e: Exception) {
          return body
        }
      }
      return body
    }

    @Throws(Exception::class)
    private fun getChankedHttpBody(input_data: ByteArray): ByteArray? {
      // TODO 改行コードの対応
      var search_word = "\r\n".toByteArray()
      var index: Int
      var start_index = 0
      var body = byteArrayOf()
      while (
        Utils.indexOf(input_data, start_index, input_data.size, search_word).also { index = it } >=
          0
      ) {
        try {
          var chank_header = ArrayUtils.subarray(input_data, start_index, index)
          var chank_length_str =
            String(chank_header, StandardCharsets.UTF_8).replace(Regex("^0+([^0].*)$"), "$1")
          var chank_length = chank_length_str.trim().toInt(16)
          if (chank_length == 0) {
            return body
          }
          var chank =
            ArrayUtils.subarray(
              input_data,
              index + search_word.size,
              index + search_word.size + chank_length,
            )
          body += chank
          start_index = index + search_word.size * 2 + chank_length
        } catch (e: Exception) {
          return null
        }
      }
      return null
    }
  }
}
