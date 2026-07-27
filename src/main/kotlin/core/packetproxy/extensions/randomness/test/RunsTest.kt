package packetproxy.extensions.randomness.test

// source code is from: NIST SP 800-22 rev1-a
// https://www.nist.gov/disclaimer

import org.apache.commons.math3.special.Erf

class RunsTest : RandomnessTest() {
  override fun run(e: Array<Array<Int>>): DoubleArray {
    var n = 0
    for (i in e.indices) {
      n = e[i].size
    }
    var p = DoubleArray(n)
    for (i in 0 until n) {
      var pi = 0.0
      for (j in e.indices) {
        pi += e[j][i]
      }
      pi /= e.size
      var v = 1
      for (j in 1 until e.size) {
        if (e[j][i] != e[j - 1][i]) {
          v++
        }
      }
      var erfcArgs =
        Math.abs(v - 2.0 * e.size * pi * (1.0 - pi)) /
          (2.0 * pi * (1.0 - pi) * Math.sqrt(2.0 * e.size))
      p[i] = Erf.erfc(erfcArgs)
    }
    return p
  }
}
