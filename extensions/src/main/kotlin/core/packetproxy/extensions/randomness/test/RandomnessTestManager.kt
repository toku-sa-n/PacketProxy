/*
 * Copyright 2019 DeNA Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package packetproxy.extensions.randomness.test

import javax.swing.JComboBox
import packetproxy.util.errWithStackTrace

class RandomnessTestManager {
  private var testMap = HashMap<String, RandomnessTest>()
  private var x =
    buildList {
        var value = -3.0
        while (value <= 0.0) {
          add(value)
          value += 0.1
        }
      }
      .toDoubleArray()

  init {
    for (i in x.indices) {
      x[i] = Math.pow(10.0, x[i])
    }
  }

  fun createTestList(): JComboBox<String> {
    var testList = JComboBox<String>()
    testList.addItem("Frequency")
    testMap["Frequency"] = FrequencyTest()
    testList.addItem("Runs")
    testMap["Runs"] = RunsTest()
    testList.addItem("LongestRunOfOne")
    testMap["LongestRunOfOne"] = LongestRunOfOneTest()
    testList.addItem("MatrixRank")
    testMap["MatrixRank"] = RankTest()
    testList.addItem("LinearComplexity with 8bit")
    testMap["LinearComplexity with 8bit"] = LinearComplexityTest(8)
    testList.addItem("LinearComplexity with 32bit")
    testMap["LinearComplexity with 32bit"] = LinearComplexityTest(32)
    testList.addItem("Serial with 8bit")
    testMap["Serial with 8bit"] = SerialTest(8)
    testList.addItem("ApproximateEntropy with 8bit")
    testMap["ApproximateEntropy with 8bit"] = ApproximateEntropyTest(8)
    testList.addItem("CUsUM with forward")
    testMap["CUsUM with forward"] = CUsUMTest(0)
    testList.addItem("CUsUM with backward")
    testMap["CUsUM with backward"] = CUsUMTest(1)
    return testList
  }

  // return list of (x, y)
  fun analyze(key: String, preprocessed: ArrayList<Array<Int>>): Array<DoubleArray> {
    var res = Array(x.size) { DoubleArray(2) }
    try {
      var test = testMap[key]
      var pValues = test!!.run(preprocessed.toTypedArray())
      for (i in res.indices) {
        var count = 0
        for (pValue in pValues) {
          if (x[i] > pValue) {
            count++
          }
        }
        res[i][0] = x[i]
        res[i][1] = count.toDouble()
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
    return res
  }
}
