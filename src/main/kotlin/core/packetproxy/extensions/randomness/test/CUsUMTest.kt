package packetproxy.extensions.randomness.test

// source code is from: NIST SP 800-22 rev1-a
// https://www.nist.gov/disclaimer

import org.apache.commons.math3.distribution.NormalDistribution

class CUsUMTest(private var mode: Int) : RandomnessTest() {
  private var dist = NormalDistribution()

  override fun run(e: Array<Array<Int>>): DoubleArray {
    var n = 0
    for (i in e.indices) {
      n = e[i].size
    }
    var p = DoubleArray(n)
    for (j in 0 until n) {
      var s = 0
      var sup = 0
      var inf = 0
      var z = 0
      var zInv = 0
      for (i in e.indices) {
        if (e[i][j] == 1) {
          s++
        } else {
          s--
        }
        sup = Math.max(sup, s)
        inf = Math.min(inf, s)
        z = Math.max(sup, -inf)
        zInv = Math.max(sup - s, s - inf)
      }
      var sum1 = 0.0
      var sum2 = 0.0
      if (mode == 0) {
        for (k in (-e.size / z + 1) / 4..(n / z - 1) / 4) {
          sum1 += dist.cumulativeProbability((4 * k + 1) * z / Math.sqrt(n.toDouble()))
          sum1 -= dist.cumulativeProbability((4 * k - 1) * z / Math.sqrt(n.toDouble()))
        }
        for (k in (-e.size / z - 3) / 4..(n / z - 1) / 4) {
          sum2 += dist.cumulativeProbability((4 * k + 3) * z / Math.sqrt(n.toDouble()))
          sum2 -= dist.cumulativeProbability((4 * k + 1) * z / Math.sqrt(n.toDouble()))
        }
      } else {
        for (k in (-e.size / zInv + 1) / 4..(n / zInv - 1) / 4) {
          sum1 += dist.cumulativeProbability((4 * k + 1) * zInv / Math.sqrt(n.toDouble()))
          sum1 -= dist.cumulativeProbability((4 * k - 1) * zInv / Math.sqrt(n.toDouble()))
        }
        for (k in (-e.size / zInv - 3) / 4..(n / zInv - 1) / 4) {
          sum2 += dist.cumulativeProbability((4 * k + 3) * zInv / Math.sqrt(n.toDouble()))
          sum2 -= dist.cumulativeProbability((4 * k + 1) * zInv / Math.sqrt(n.toDouble()))
        }
      }
      p[j] = 1.0 - sum1 + sum2
    }
    return p
  }
}
