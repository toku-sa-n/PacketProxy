package packetproxy.extensions.randomness.test

// source code is from: NIST SP 800-22 rev1-a
// https://www.nist.gov/disclaimer

import org.apache.commons.math3.distribution.GammaDistribution
import packetproxy.util.log

class LongestRunOfOneTest : RandomnessTest() {
  override fun run(e: Array<Array<Int>>): DoubleArray {
    var n = e.size
    if (n < 128) {
      log("[Warn] bit length is not suitable for LongestRunOfOne test. Please collect more tokens.")
      return DoubleArray(if (e.isNotEmpty()) e[0].size else 0)
    }
    var k = 0
    var m = 0
    var v: IntArray
    var pi: DoubleArray
    if (n < 6272) {
      k = 3
      m = 8
      v = intArrayOf(1, 2, 3, 4)
      pi = doubleArrayOf(0.21484375, 0.3671875, 0.23046875, 0.1875)
    } else if (n < 750000) {
      k = 5
      m = 128
      v = intArrayOf(4, 5, 6, 7, 8, 9)
      pi =
        doubleArrayOf(0.1174035788, 0.242955959, 0.249363483, 0.17517706, 0.102701071, 0.112398847)
    } else {
      k = 6
      m = 10000
      v = intArrayOf(10, 11, 12, 13, 14, 15, 16)
      pi = doubleArrayOf(0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727)
    }
    var dist = GammaDistribution(k / 2.0, 1.0)
    var nu = IntArray(k + 1)
    var numberOfBlocks = e.size / m
    for (i in e.indices) {
      n = e[i].size
    }
    var p = DoubleArray(n)
    for (bitIndex in 0 until n) {
      for (i in 0 until numberOfBlocks) {
        var longestRun = 0
        var r = 0
        for (j in 0 until m) {
          var idx = i * m + j
          if (e[idx][bitIndex] == 1) {
            longestRun = Math.max(longestRun, ++r)
          } else {
            r = 0
          }
        }
        if (longestRun < v[0]) {
          nu[0]++
        }
        for (j in 0..k) {
          if (longestRun == v[j]) {
            nu[j]++
          }
        }
        if (longestRun > v[k]) {
          nu[k]++
        }
      }
      var chi2 = 0.0
      for (i in 0..k) {
        chi2 +=
          (nu[i] - numberOfBlocks * pi[i]) * (nu[i] - numberOfBlocks * pi[i]) /
            (numberOfBlocks * pi[i])
      }
      p[bitIndex] = 1 - dist.cumulativeProbability(chi2 / 2.0)
    }
    return p
  }
}
