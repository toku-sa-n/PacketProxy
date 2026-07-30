/*
 * Copyright 2026 DeNA Co., Ltd.
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
package packetproxy.model

import com.j256.ormlite.dao.Dao
import com.j256.ormlite.dao.DaoManager
import com.j256.ormlite.jdbc.JdbcConnectionSource
import com.j256.ormlite.logger.LocalLog
import com.j256.ormlite.support.ConnectionSource
import com.j256.ormlite.table.TableUtils
import java.net.InetSocketAddress
import java.nio.file.Files
import java.sql.DriverManager
import java.util.concurrent.TimeUnit
import org.openjdk.jmh.annotations.Benchmark
import org.openjdk.jmh.annotations.BenchmarkMode
import org.openjdk.jmh.annotations.Level
import org.openjdk.jmh.annotations.Mode
import org.openjdk.jmh.annotations.OutputTimeUnit
import org.openjdk.jmh.annotations.Param
import org.openjdk.jmh.annotations.Scope
import org.openjdk.jmh.annotations.Setup
import org.openjdk.jmh.annotations.State
import org.openjdk.jmh.annotations.TearDown
import org.openjdk.jmh.infra.Blackhole

private fun silenceOrmliteLogs() {
  System.setProperty(LocalLog.LOCAL_LOG_LEVEL_PROPERTY, "ERROR")
}

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class PacketSqliteBenchmark {
  @Param("4096", "102400") var blobSize = 0

  @Param("delete", "wal") lateinit var journalMode: String

  private lateinit var dbPath: String
  private lateinit var source: ConnectionSource
  private lateinit var dao: Dao<Packet, Int>
  private lateinit var payload: ByteArray
  private var packetId = 0

  @Setup(Level.Trial)
  fun setupTrial() {
    silenceOrmliteLogs()
    val temp = Files.createTempFile("pp-jmh-packets-", ".sqlite3")
    dbPath = temp.toAbsolutePath().toString()
    Files.deleteIfExists(temp)
    Class.forName("org.sqlite.JDBC")
    DriverManager.getConnection("jdbc:sqlite:$dbPath").use { conn ->
      conn.createStatement().use { st ->
        st.execute("PRAGMA journal_mode=$journalMode")
        st.execute("PRAGMA synchronous=NORMAL")
      }
    }
    source = JdbcConnectionSource("jdbc:sqlite:$dbPath")
    TableUtils.createTableIfNotExists(source, Packet::class.java)
    dao = DaoManager.createDao(source, Packet::class.java)
  }

  @Setup(Level.Iteration)
  fun setupIteration() {
    payload = ByteArray(blobSize) { (it % 251).toByte() }
    val packet =
      Packet(
        8080,
        InetSocketAddress("127.0.0.1", 12345),
        InetSocketAddress("127.0.0.1", 443),
        "example.com",
        true,
        "HTTP",
        "",
        Packet.Direction.CLIENT,
        1,
        1L,
      )
    packet.setReceivedData(payload)
    packet.setDecodedData(payload)
    packet.setModifiedData(payload)
    packet.setSentData(payload)
    dao.create(packet)
    packetId = packet.getId()
  }

  @TearDown(Level.Trial)
  fun tearDown() {
    source.close()
    Files.deleteIfExists(java.nio.file.Paths.get(dbPath))
  }

  @Benchmark
  fun createOrUpdateFourBlobs(bh: Blackhole) {
    val packet = dao.queryForId(packetId)
    packet.setReceivedData(payload)
    packet.setDecodedData(payload)
    packet.setModifiedData(payload)
    packet.setSentData(payload)
    bh.consume(dao.createOrUpdate(packet))
  }

  @Benchmark
  fun queryById(bh: Blackhole) {
    bh.consume(dao.queryForId(packetId))
  }
}

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@BenchmarkMode(Mode.AverageTime)
open class PacketSqliteMultiUpdateBenchmark {
  @Param("1", "3", "5") var updatesPerPacket = 0

  private lateinit var dbPath: String
  private lateinit var source: ConnectionSource
  private lateinit var dao: Dao<Packet, Int>
  private lateinit var payload: ByteArray

  @Setup(Level.Trial)
  fun setupTrial() {
    silenceOrmliteLogs()
    val temp = Files.createTempFile("pp-jmh-multi-", ".sqlite3")
    dbPath = temp.toAbsolutePath().toString()
    Files.deleteIfExists(temp)
    Class.forName("org.sqlite.JDBC")
    DriverManager.getConnection("jdbc:sqlite:$dbPath").use { conn ->
      conn.createStatement().use { st -> st.execute("PRAGMA journal_mode=delete") }
    }
    source = JdbcConnectionSource("jdbc:sqlite:$dbPath")
    TableUtils.createTableIfNotExists(source, Packet::class.java)
    dao = DaoManager.createDao(source, Packet::class.java)
    payload = ByteArray(4096) { (it % 251).toByte() }
  }

  @TearDown(Level.Trial)
  fun tearDown() {
    source.close()
    Files.deleteIfExists(java.nio.file.Paths.get(dbPath))
  }

  @Benchmark
  fun simulateHotPathUpdates(bh: Blackhole) {
    val packet =
      Packet(
        8080,
        InetSocketAddress("127.0.0.1", 12345),
        InetSocketAddress("127.0.0.1", 443),
        "example.com",
        true,
        "HTTP",
        "",
        Packet.Direction.CLIENT,
        1,
        System.nanoTime(),
      )
    packet.setReceivedData(payload)
    dao.create(packet)
    repeat(updatesPerPacket) { i ->
      when (i % 4) {
        0 -> packet.setDecodedData(payload)
        1 -> packet.setModifiedData(payload)
        2 -> packet.setSentData(payload)
        else -> packet.setReceivedData(payload)
      }
      dao.createOrUpdate(packet)
    }
    bh.consume(packet.getId())
  }
}
