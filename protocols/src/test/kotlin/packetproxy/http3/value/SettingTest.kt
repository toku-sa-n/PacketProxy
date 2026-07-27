package packetproxy.http3.value

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SettingTest {
  @Test
  fun `Builderが動作すること`() {
    val setting = Setting.builder().enableMetaData(1).qpackMaxTableCapacity(100).build()
    assertThat(setting.enableMetaData).isEqualTo(1)
    assertThat(setting.qpackMaxTableCapacity).isEqualTo(100)
    assertThat(setting.h3Datagram).isZero()
    assertThat(setting.enableConnectProtocol).isZero()
    assertThat(setting.maxFieldSectionSize).isEqualTo(Long.MAX_VALUE)
  }
}
