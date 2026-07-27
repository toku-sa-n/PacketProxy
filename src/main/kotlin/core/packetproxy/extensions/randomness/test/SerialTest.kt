package packetproxy.extensions.randomness.test

// source code is from: NIST SP 800-22 rev1-a
// https://www.nist.gov/disclaimer

import org.apache.commons.math3.distribution.GammaDistribution

class SerialTest(private var m: Int) : RandomnessTest() {
  override fun run(e: Array<Array<Int>>): DoubleArray {
    var n = 0
    for (i in e.indices) {
      n = e[i].size
    }
    var p = DoubleArray(n)
    for (i in 0 until n) {
      var pSim0 = psi2(m, e.size, e, i)
      var pSim1 = psi2(m - 1, e.size, e, i)
      var pSim2 = psi2(m - 2, e.size, e, i)
      var del1 = pSim0 - pSim1
      var del2 = pSim0 - 2.0 * pSim1 + pSim2
      var dist = GammaDistribution(Math.abs(del1 / 2.0), 1.0)
      var p1 = 1 - dist.cumulativeProbability(Math.pow(2.0, m - 1.0))
      dist = GammaDistribution(Math.abs(del2 / 2.0), 1.0)
      var p2 = 1 - dist.cumulativeProbability(Math.pow(2.0, m - 2.0))
      p[i] = Math.min(p1, p2)
    }
    return p
  }

  private fun psi2(m: Int, n: Int, e: Array<Array<Int>>, idx: Int): Double {
    if (m == 0 || m == -1) {
      return 0.0
    }
    var numOfBlocks = n
    var powLen = Math.pow(2.0, m + 1.0).toInt() - 1
    var counts = IntArray(powLen)
    for (i in 0 until numOfBlocks) {
      var k = 1
      for (j in 0 until m) {
        if (e[(i + j) % n][idx] == 0) {
          k *= 2
        } else {
          k = 2 * k + 1
        }
      }
      counts[k - 1]++
    }
    var sum = 0.0
    for (i in Math.pow(2.0, m.toDouble()).toInt() - 1 until powLen) {
      sum += Math.pow(counts[i].toDouble(), 2.0)
    }
    return sum * Math.pow(2.0, m.toDouble()) / n - n
  }
}
