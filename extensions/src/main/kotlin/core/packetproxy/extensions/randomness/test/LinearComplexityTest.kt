package packetproxy.extensions.randomness.test

// source code is from: NIST SP 800-22 rev1-a
// https://www.nist.gov/disclaimer

import org.apache.commons.math3.distribution.GammaDistribution
import packetproxy.util.Logging.log

class LinearComplexityTest(private var m: Int) : RandomnessTest() {
  override fun run(e: Array<Array<Int>>): DoubleArray {
    var numberOfBlocks = e.size / m
    if (numberOfBlocks == 0) {
      log("[Warn] bit length is not suitable for Rank test. Please collect more tokens.")
      return DoubleArray(if (e.isNotEmpty()) e[0].size else 0)
    }
    var n = 0
    for (i in e.indices) {
      n = e[i].size
    }
    var p = DoubleArray(n)
    for (i in 0 until n) {
      var nu = DoubleArray(k + 1)
      for (j in 0 until numberOfBlocks) {
        var b = IntArray(m)
        var c = IntArray(m)
        var polynomial = IntArray(m)
        var temporary = IntArray(m)
        var linearComplexity = 0
        var previous = -1
        var discrepancy = 0
        c[0] = 1
        b[0] = 1
        var temporaryN = 0
        while (temporaryN < m) {
          discrepancy = e[j * m + temporaryN][i]
          for (l in 0..linearComplexity) {
            discrepancy += c[l] * e[j * m + temporaryN - l][i]
          }
          discrepancy = discrepancy and 1
          if (discrepancy == 1) {
            for (l in 0 until m) {
              temporary[l] = c[l]
              polynomial[l] = 0
            }
            for (l in 0 until m) {
              if (b[l] == 1) {
                polynomial[l + temporaryN - previous] = 1
              }
            }
            for (l in 0 until m) {
              c[l] = (c[l] + polynomial[l]) and 1
            }
            if (linearComplexity <= temporaryN / 2) {
              linearComplexity = temporaryN + 1 - linearComplexity
              previous = temporaryN
              for (l in 0 until m) {
                b[l] = temporary[l]
              }
            }
          }
          temporaryN++
        }
        var sign = if (m % 2 == 1) -1 else 1
        var mean =
          m / 2.0 + (9.0 + sign) / 36.0 - 1.0 / Math.pow(2.0, m.toDouble()) * (m / 3.0 + 2.0 / 9.0)
        sign = if (m % 2 == 0) 1 else -1
        var temporaryT = sign * (linearComplexity - mean) + 2.0 / 9.0
        if (temporaryT <= -2.5) {
          nu[0]++
        } else if (temporaryT <= -1.5) {
          nu[1]++
        } else if (temporaryT <= -0.5) {
          nu[2]++
        } else if (temporaryT <= 0.5) {
          nu[3]++
        } else if (temporaryT <= 1.5) {
          nu[4]++
        } else if (temporaryT <= 2.5) {
          nu[5]++
        } else {
          nu[6]++
        }
      }
      var chi2 = 0.00
      for (j in 0..k) {
        chi2 += Math.pow(nu[j] - numberOfBlocks * pi[j], 2.0) / (numberOfBlocks * pi[j])
      }
      var dist = GammaDistribution(k / 2.0, 1.0)
      p[i] = 1 - dist.cumulativeProbability(chi2 / 2.0)
    }
    return p
  }

  companion object {
    private var pi = doubleArrayOf(0.010417, 0.03125, 0.12500, 0.50000, 0.25000, 0.06250, 0.020833)
    private var k = 6
  }
}
