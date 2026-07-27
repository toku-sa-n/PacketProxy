package packetproxy.gui

import com.google.common.collect.ImmutableList
import java.nio.charset.StandardCharsets
import packetproxy.common.I18nString
import packetproxy.common.Range
import packetproxy.model.OneShotPacket
import packetproxy.vulchecker.VulCheckPattern
import packetproxy.vulchecker.VulChecker
import packetproxy.vulchecker.generator.Generator

class GUIVulCheckManager(
  vulChecker: VulChecker,
  private var origPacket: OneShotPacket,
  private var origRange: Range,
) {
  private var generators = vulChecker.getGenerators()
  private var patternMap = mutableMapOf<String, VulCheckPattern>()
  private var enableMap = mutableMapOf<String, Boolean>()
  private var generatedMap = mutableMapOf<String, Boolean>()

  init {
    generators.forEach { generatedMap[it.getName()] = false }
    generateOnStart()
  }

  fun generate(name: String) = generateFromOrig(findGenerator(name))

  fun extractMacro(generatorName: String, data: ByteArray) =
    findGenerator(generatorName).extractMacro(data)

  fun saveVulCheckPattern(name: String, pattern: VulCheckPattern) {
    if (isEnabled(name)) patternMap[name] = pattern
  }

  fun getGenerators(): ImmutableList<Generator> = generators

  fun getAllVulCheckPattern(): ImmutableList<VulCheckPattern> =
    ImmutableList.copyOf(generators.map { findVulCheckPattern(it.getName()) })

  fun getAllEnabledVulCheckPattern(): ImmutableList<VulCheckPattern> =
    ImmutableList.copyOf(
      generators.filter { isEnabled(it.getName()) }.map { findVulCheckPattern(it.getName()) }
    )

  fun findVulCheckPattern(name: String): VulCheckPattern =
    if (isEnabled(name)) patternMap.getValue(name) else createEmptyPattern(origPacket)

  fun isEnabled(name: String): Boolean = enableMap[name] ?: false

  fun setEnabled(name: String, enabled: Boolean) {
    enableMap[name] = enabled
    if (enabled && generatedMap[name] != true) generate(name)
  }

  private fun createEmptyPattern(packet: OneShotPacket): VulCheckPattern {
    var emptyPacket = packet.clone() as OneShotPacket
    emptyPacket.setData(
      I18nString.get("Activate the checkbox to generate a pattern")
        .toByteArray(StandardCharsets.UTF_8)
    )
    emptyPacket.setEncoder("Sample")
    emptyPacket.setAlpn("")
    return VulCheckPattern("empty", emptyPacket, null)
  }

  private fun generateOnStart() {
    generators.forEach { if (it.generateOnStart()) generateFromOrig(it) else noGenerate(it) }
  }

  private fun findGenerator(name: String): Generator = generators.first { it.getName() == name }

  private fun generateFromOrig(generator: Generator): VulCheckPattern {
    var packet = origPacket.clone() as OneShotPacket
    var generated = generator.generate(String(packet.getData(origRange), StandardCharsets.UTF_8))
    packet.replaceData(origRange, generated.toByteArray(StandardCharsets.UTF_8))
    var pattern =
      VulCheckPattern(
        generator.getName(),
        packet,
        Range.of(origRange.getPositionStart(), origRange.getPositionStart() + generated.length),
      )
    patternMap[generator.getName()] = pattern
    enableMap[generator.getName()] = true
    generatedMap[generator.getName()] = true
    return pattern
  }

  private fun noGenerate(generator: Generator): VulCheckPattern {
    var pattern =
      VulCheckPattern(generator.getName(), origPacket.clone() as OneShotPacket, origRange)
    patternMap[generator.getName()] = pattern
    enableMap[generator.getName()] = false
    return pattern
  }
}
