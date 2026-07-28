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
package packetproxy.extensions.randomness

import com.google.re2j.Pattern
import java.awt.BasicStroke
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.nio.charset.StandardCharsets
import java.text.NumberFormat
import java.util.Base64
import java.util.concurrent.CompletableFuture
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JFormattedTextField
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JProgressBar
import javax.swing.JSplitPane
import javax.swing.JTextField
import javax.swing.KeyStroke
import javax.swing.text.NumberFormatter
import org.apache.commons.codec.binary.Hex
import org.jfree.chart.ChartPanel
import org.jfree.chart.JFreeChart
import org.jfree.chart.axis.LogAxis
import org.jfree.chart.axis.NumberAxis
import org.jfree.chart.plot.IntervalMarker
import org.jfree.chart.plot.XYPlot
import org.jfree.chart.renderer.xy.StandardXYItemRenderer
import org.jfree.data.Range
import org.jfree.data.xy.XYSeries
import org.jfree.data.xy.XYSeriesCollection
import packetproxy.CoreServiceExtension
import packetproxy.CoreServices
import packetproxy.controller.ResendController
import packetproxy.controller.ResendController.ResendWorker
import packetproxy.extensions.randomness.test.RandomnessTestManager
import packetproxy.gui.GUIBulkSenderData
import packetproxy.gui.GUIMain
import packetproxy.gui.GuiServiceExtension
import packetproxy.model.Extension
import packetproxy.model.OneShotPacket
import packetproxy.model.Packet
import packetproxy.util.errWithStackTrace
import packetproxy.util.log

class RandomnessExtension : Extension, CoreServiceExtension, GuiServiceExtension {
  private var sendPacket: OneShotPacket? = null
  private var recvPackets = HashMap<Int, OneShotPacket>()
  private var tokens = ArrayList<String>()
  private lateinit var regexField: JTextField
  private lateinit var countField: JFormattedTextField
  private lateinit var requestProgressBar: JProgressBar
  private lateinit var preprocess: JComboBox<String>
  private lateinit var testMethods: JComboBox<String>
  private lateinit var chart: JFreeChart
  private lateinit var sendData: GUIBulkSenderData
  private var sendPacketId = 0
  private lateinit var resendController: ResendController
  private lateinit var guiMain: GUIMain
  private val randomnessTestManager = RandomnessTestManager()

  constructor() : super() {
    initialize()
  }

  @Throws(Exception::class)
  constructor(name: String, path: String) : super(name, path) {
    initialize()
  }

  @Throws(Exception::class)
  override fun createPanel(): JComponent {
    var vsplitPanel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    vsplitPanel.add(createSendPanel())
    vsplitPanel.add(createResultPanel())
    vsplitPanel.setDividerLocation(0.5)
    return vsplitPanel
  }

  @Throws(Exception::class)
  fun add(oneshot: OneShotPacket?, packetId: Int) {
    oneshot!!.setId(sendPacketId)
    sendPacket = oneshot
    sendPacketId++
    sendData.setData(oneshot.getData())
  }

  override fun historyClickHandler(packetProvider: () -> Packet): JMenuItem {
    return createMenuItem("send to Randomness Checker", -1, null) {
      try {
        var packet = packetProvider()
        add(packet.getOneShotFromModifiedData(), packet.getId())
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
  }

  override fun initialize(coreServices: CoreServices) {
    resendController = coreServices.resendController
  }

  override fun initialize(guiMain: GUIMain) {
    this.guiMain = guiMain
  }

  private fun initialize() {
    setName("Randomness")
  }

  @Throws(Exception::class)
  private fun createSendPanel(): JComponent {
    sendData =
      GUIBulkSenderData(guiMain, GUIBulkSenderData.Type.CLIENT) { data ->
        var packet = sendPacket
        if (packet != null) {
          packet.setData(data)
        }
      }
    var regexPanel = JPanel()
    regexPanel.background = Color.WHITE
    regexPanel.layout = BoxLayout(regexPanel, BoxLayout.X_AXIS)
    regexPanel.add(JLabel("RegExp to pickup:"))
    regexField =
      JTextField(
        "X-PacketProxy-HTTP2-UUID: ([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})"
      )
    regexField.maximumSize = Dimension(Short.MAX_VALUE.toInt(), regexField.minimumSize.height)
    regexPanel.add(regexField)

    var countPanel = JPanel()
    countPanel.background = Color.WHITE
    countPanel.layout = BoxLayout(countPanel, BoxLayout.X_AXIS)
    countPanel.add(JLabel("count:"))
    var countFormat = NumberFormat.getIntegerInstance()
    countFormat.isGroupingUsed = false
    var countFormatter = NumberFormatter(countFormat)
    countFormatter.valueClass = Integer::class.java
    countFormatter.allowsInvalid = false
    countField = JFormattedTextField(countFormatter)
    countField.value = 100
    countField.maximumSize = Dimension(Short.MAX_VALUE.toInt(), regexField.minimumSize.height)
    countPanel.add(countField)

    requestProgressBar = JProgressBar()
    requestProgressBar.isStringPainted = true
    requestProgressBar.minimum = 0

    var sendButton = JButton("Start collection")
    sendButton.addActionListener {
      try {
        var pattern = Pattern.compile(regexField.text)
        var count = countField.text.toInt()
        if (count < 0) {
          return@addActionListener
        }
        requestProgressBar.maximum = count
        requestProgressBar.value = 0
        recvPackets.clear()
        tokens.clear()
        var future = CompletableFuture.completedFuture("send packets for analysis")
        for (i in 0 until count) {
          future =
            future.thenApplyAsync { argument ->
              try {
                resendController.resend(
                  resendController.run {
                    object : ResendWorker(sendPacket!!, 1) {
                      override fun process(oneshots: MutableList<OneShotPacket>) {
                        var id = requestProgressBar.value
                        for (oneshot in oneshots) {
                          recvPackets[id++] = oneshot
                        }
                        requestProgressBar.value += oneshots.size
                        if (recvPackets.size == count) {
                          log("all packet received")
                          for (packet in recvPackets.values) {
                            var content = toUTF8(packet.getData())
                            var match = pattern.matcher(content)
                            if (match.find()) {
                              var token = ""
                              for (idx in 1..match.groupCount()) {
                                token += match.group(idx)
                              }
                              tokens.add(token)
                            }
                          }
                          JOptionPane.showMessageDialog(
                            guiMain,
                            String.format("get %d tokens", tokens.size),
                            "Packet collection finished",
                            JOptionPane.PLAIN_MESSAGE,
                          )
                        }
                      }
                    }
                  }
                )
              } catch (e: Exception) {
                errWithStackTrace(e)
              }
              argument
            }
          future =
            future.thenApplyAsync { argument ->
              try {
                Thread.sleep(100)
              } catch (e: Exception) {
                errWithStackTrace(e)
              }
              argument
            }
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    var clearButton = JButton("clear")
    clearButton.addActionListener {
      try {
        sendPacket = null
        recvPackets.clear()
        sendData.setData(ByteArray(0))
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    var buttonPanel = JPanel()
    buttonPanel.add(sendButton)
    buttonPanel.add(clearButton)
    buttonPanel.layout = BoxLayout(buttonPanel, BoxLayout.LINE_AXIS)
    var optionPanel = JPanel()
    optionPanel.layout = BoxLayout(optionPanel, BoxLayout.Y_AXIS)
    optionPanel.add(regexPanel)
    optionPanel.add(countPanel)
    optionPanel.add(requestProgressBar)
    optionPanel.add(buttonPanel)
    var leftHalf = JPanel()
    leftHalf.layout = BoxLayout(leftHalf, BoxLayout.Y_AXIS)
    leftHalf.add(sendData.createPanel())
    leftHalf.add(optionPanel)
    leftHalf.alignmentX = Component.CENTER_ALIGNMENT
    return leftHalf
  }

  @Throws(Exception::class)
  private fun createResultPanel(): JComponent {
    var preprocessPanel = JPanel()
    preprocessPanel.background = Color.WHITE
    preprocessPanel.layout = BoxLayout(preprocessPanel, BoxLayout.X_AXIS)
    preprocessPanel.add(JLabel("preprocess token to binary:"))
    preprocess = JComboBox()
    preprocess.addItem("hex")
    preprocess.addItem("base64")
    preprocess.addItem("int64")
    preprocessPanel.add(preprocess)
    var testPanel = JPanel()
    testPanel.background = Color.WHITE
    testPanel.layout = BoxLayout(testPanel, BoxLayout.X_AXIS)
    testPanel.add(JLabel("testing method:"))
    testMethods = randomnessTestManager.createTestList()
    testPanel.add(testMethods)
    var analyzeButton = JButton("Start analysis")
    analyzeButton.addActionListener {
      try {
        var preprocessKey = preprocess.selectedItem as String
        var testMethodKey = testMethods.selectedItem as String
        var preprocessed = ArrayList<Array<Int>>()
        when (preprocessKey) {
          "hex" ->
            for (token in tokens) {
              var bytes = Hex.decodeHex(token.toCharArray())
              var array = ArrayList<Int>()
              for (byte in bytes) {
                for (j in 7 downTo 0) {
                  array.add((byte.toInt() shr j) and 1)
                }
              }
              preprocessed.add(array.toTypedArray())
            }
          "base64" ->
            for (token in tokens) {
              var bytes = Base64.getDecoder().decode(token)
              var array = ArrayList<Int>()
              for (byte in bytes) {
                for (j in 7 downTo 0) {
                  array.add((byte.toInt() shr j) and 1)
                }
              }
              preprocessed.add(array.toTypedArray())
            }
          "int64" ->
            for (token in tokens) {
              var number = token.toLong()
              var array = ArrayList<Int>()
              for (j in 63 downTo 0) {
                array.add(((number shr j) and 1).toInt())
              }
              preprocessed.add(array.toTypedArray())
            }
          else -> throw Exception("preprocessKey $preprocessKey not found")
        }
        var points = randomnessTestManager.analyze(testMethodKey, preprocessed)
        var series = XYSeries("data", false)
        for (point in points) {
          series.add(point[0], point[1])
        }
        var collection = XYSeriesCollection()
        collection.addSeries(series)
        chart.xyPlot.dataset = collection
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }
    var buttonPanel = JPanel()
    buttonPanel.add(analyzeButton)
    buttonPanel.layout = BoxLayout(buttonPanel, BoxLayout.LINE_AXIS)
    var xAxis = LogAxis()
    xAxis.base = 10.0
    xAxis.label = "p-value"
    xAxis.range = Range(0.001, 1.0)
    var yAxis = NumberAxis()
    yAxis.label = "number of randomized bits"
    var sampleCollection = XYSeriesCollection()
    var marker1 = IntervalMarker(0.001, 0.01)
    marker1.paint = Color(0xA5, 0xD6, 0xA7)
    marker1.alpha = 0.5f
    var marker2 = IntervalMarker(0.01, 0.1)
    marker2.paint = Color(0xFF, 0xF5, 0x9D)
    marker2.alpha = 0.5f
    var marker3 = IntervalMarker(0.1, 1.0)
    marker3.paint = Color(0xEF, 0x9A, 0x9A)
    marker3.alpha = 0.5f
    var xyPlot = XYPlot(sampleCollection, xAxis, yAxis, StandardXYItemRenderer())
    xyPlot.addDomainMarker(marker1)
    xyPlot.addDomainMarker(marker2)
    xyPlot.addDomainMarker(marker3)
    xyPlot.renderer.setSeriesStroke(0, BasicStroke(2.0f))
    chart = JFreeChart("p-value and randomized bits", xyPlot)
    chart.removeLegend()
    var chartPanel = ChartPanel(chart)
    var rightHalf = JPanel()
    rightHalf.add(preprocessPanel)
    rightHalf.add(testPanel)
    rightHalf.add(buttonPanel)
    rightHalf.add(chartPanel)
    rightHalf.layout = BoxLayout(rightHalf, BoxLayout.Y_AXIS)
    return rightHalf
  }

  private fun toUTF8(raw: ByteArray): String = String(raw, StandardCharsets.UTF_8)

  private fun createMenuItem(
    name: String,
    key: Int,
    hotkey: KeyStroke?,
    listener: java.awt.event.ActionListener,
  ): JMenuItem {
    var output = JMenuItem(name)
    if (key >= 0) {
      output.mnemonic = key
    }
    if (hotkey != null) {
      output.accelerator = hotkey
    }
    output.addActionListener(listener)
    return output
  }
}
