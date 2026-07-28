package packetproxy.extensions.randomness.test

// source code is from: NIST SP 800-22 rev1-a
// https://www.nist.gov/disclaimer

import org.apache.commons.math3.distribution.GammaDistribution
import org.ejml.simple.SimpleMatrix
import packetproxy.util.log

class RankTest : RandomnessTest() {
  override fun run(e: Array<Array<Int>>): DoubleArray {
    var numberOfMatrices = e.size / (32 * 32)
    if (numberOfMatrices == 0) {
      log("[Warn] bit length is not suitable for Rank test. Please collect more tokens.")
      return DoubleArray(if (e.isNotEmpty()) e[0].size else 0)
    }
    var n = 0
    for (i in e.indices) {
      n = e[i].size
    }
    var p = DoubleArray(n)
    for (i in 0 until n) {
      var mat = SimpleMatrix(32, 32)
      var r = 32
      var product = 1.0
      for (j in 0 until r) {
        product *=
          (1.0 - Math.pow(2.0, j - 32.0)) * (1 - Math.pow(2.0, j - 32.0)) /
            (1 - Math.pow(2.0, j - r.toDouble()))
      }
      var p32 = Math.pow(2.0, r * (32 + 32 - r) - 32 * 32.0) * product
      r = 31
      product = 1.0
      for (j in 0 until r) {
        product *=
          (1.0 - Math.pow(2.0, j - 32.0)) * (1 - Math.pow(2.0, j - 32.0)) /
            (1 - Math.pow(2.0, j - r.toDouble()))
      }
      var p31 = Math.pow(2.0, r * (32 + 32 - r) - 32 * 32.0) * product
      var p30 = 1 - (p32 + p31)
      var f32 = 0.0
      var f31 = 0.0
      for (j in 0 until numberOfMatrices) {
        for (k in 0 until 32) {
          for (l in 0 until 32) {
            mat.set(k, l, e[j * (32 * 32) + k * 32 + l][i].toDouble())
          }
        }
        when (mat.svd().rank()) {
          32 -> f32++
          31 -> f31++
        }
      }
      var f30 = numberOfMatrices - (f32 + f31)
      var chiSquared =
        Math.pow(f32 - numberOfMatrices * p32, 2.0) / (numberOfMatrices * p32) +
          Math.pow(f31 - numberOfMatrices * p31, 2.0) / (numberOfMatrices * p31) +
          Math.pow(f30 - numberOfMatrices * p30, 2.0) / (numberOfMatrices * p30)
      var dist = GammaDistribution(numberOfMatrices / 2.0, 1.0)
      p[i] = 1 - dist.cumulativeProbability(chiSquared / 2.0)
    }
    return p
  }
}
