package packetproxy.gui

/**
 * Splits a History request summary (`METHOD URL` from HTTP encoders, or an opaque string) into
 * table columns so a long host does not hide the path.
 */
data class RequestSummaryParts(val method: String, val host: String, val path: String)

fun splitHttpUrl(url: String): Pair<String, String> {
  val withoutScheme = url.substringAfter("://", missingDelimiterValue = url)
  val slash = withoutScheme.indexOf('/')
  if (slash < 0) {
    return withoutScheme to "/"
  }
  val host = withoutScheme.substring(0, slash)
  val path = withoutScheme.substring(slash)
  return host to path
}

fun splitRequestSummary(summary: String): RequestSummaryParts {
  if (summary.isEmpty()) {
    return RequestSummaryParts("", "", "")
  }
  val space = summary.indexOf(' ')
  if (space < 0) {
    return RequestSummaryParts("", "", summary)
  }
  val method = summary.substring(0, space)
  val rest = summary.substring(space + 1).trim()
  if (rest.isEmpty()) {
    return RequestSummaryParts(method, "", "")
  }
  // HTTP-style: METHOD + absolute URL (or authority[/path]). Otherwise keep opaque text in Path.
  if (rest.contains("://") || looksLikeHttpAuthorityAndPath(rest)) {
    val (host, path) = splitHttpUrl(rest)
    return RequestSummaryParts(method, host, path)
  }
  if (!rest.contains('/') && (rest.contains('.') || rest.contains(':'))) {
    // METHOD host (no path), e.g. "OPTIONS example.com:443"
    return RequestSummaryParts(method, rest, "/")
  }
  return RequestSummaryParts("", "", summary)
}

private fun looksLikeHttpAuthorityAndPath(rest: String): Boolean {
  // e.g. "example.com/api" without scheme
  val slash = rest.indexOf('/')
  if (slash <= 0) {
    return false
  }
  val authority = rest.substring(0, slash)
  return !authority.contains(' ') && (authority.contains('.') || authority.contains(':'))
}
