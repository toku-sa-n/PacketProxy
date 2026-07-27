package packetproxy.extensions.randomness.test

// source code is from: NIST SP 800-22 rev1-a
// https://www.nist.gov/disclaimer

import org.apache.commons.math3.special.Erf

class FrequencyTest : RandomnessTest() {
  override fun run(e: Array<Array<Int>>): DoubleArray {
    var n = 0
    for (i in e.indices) {
      n = e[i].size
      for (j in 0 until n) {
        e[i][j] = 2 * e[i][j] - 1
      }
    }
    var p = DoubleArray(n)
    for (i in 0 until n) {
      var s = 0
      for (j in e.indices) {
        s += e[j][i]
      }
      var z = Math.abs(s.toDouble()) / Math.sqrt(e.size.toDouble())
      p[i] = 1.0 - Erf.erf(z / Math.sqrt(2.0))
    }
    return p
  }
}
