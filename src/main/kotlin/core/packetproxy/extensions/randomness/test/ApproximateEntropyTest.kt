package packetproxy.extensions.randomness.test

// source code is from: NIST SP 800-22 rev1-a
// https://www.nist.gov/disclaimer

import org.apache.commons.math3.distribution.GammaDistribution

class ApproximateEntropyTest(private var m: Int) : RandomnessTest() {
  override fun run(e: Array<Array<Int>>): DoubleArray {
    var dist = GammaDistribution(Math.pow(2.0, m - 1.0), 1.0)
    var n = 0
    for (i in e.indices) {
      n = e[i].size
    }
    var p = DoubleArray(n)
    var seqLength = e.size
    var apEn = DoubleArray(2)
    var r = 0
    for (i in 0 until n) {
      for (blockSize in m..m + 1) {
        if (blockSize == 0) {
          apEn[0] = 0.00
          r++
        } else {
          var numOfBlocks = seqLength.toDouble()
          var powLen = Math.pow(2.0, blockSize + 1.0).toInt() - 1
          var counts = IntArray(powLen)
          for (j in 0 until numOfBlocks.toInt()) {
            var k = 1
            for (l in 0 until blockSize) {
              k = k shl 1
              if (e[(j + l) % seqLength][i] == 1) {
                k++
              }
            }
            counts[k - 1]++
          }
          var sum = 0.0
          var idx = Math.pow(2.0, blockSize.toDouble()).toInt() - 1
          for (j in 0 until Math.pow(2.0, blockSize.toDouble()).toInt()) {
            if (counts[idx] > 0) {
              sum += counts[idx] * Math.log(counts[idx] / numOfBlocks)
            }
            idx++
          }
          sum /= numOfBlocks
          apEn[r++] = sum
        }
      }
      var apen = apEn[0] - apEn[1]
      var chi2 = 2.0 * seqLength * (Math.log(2.0) - apen)
      p[i] = 1 - dist.cumulativeProbability(chi2 / 2.0)
    }
    return p
  }
}
