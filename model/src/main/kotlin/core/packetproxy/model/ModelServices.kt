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

import packetproxy.CertCacheManager
import packetproxy.common.ClientKeyManager
import packetproxy.common.FontManager
import packetproxy.common.RecentProjectsStore
import packetproxy.util.CharSetUtility

class ModelServices(val database: Database, restorePackets: Boolean) {
  init {
    database.createDB()
  }

  val clientKeyManager = ClientKeyManager()
  val configs = Configs(database)
  val packets = Packets(database, restorePackets, configs)
  val servers = Servers(database)
  val listenPorts = ListenPorts(database)
  val filters = Filters(database)
  val modifications = Modifications(database)
  val interceptOptions = InterceptOptions(database)
  val sslPassThroughs = SSLPassThroughs(database)
  val clientCertificates = ClientCertificates(database, clientKeyManager)
  val charSets = CharSets(database)
  val resolutions = Resolutions(database)
  val resenderPackets = ResenderPackets(database)
  val extensions = Extensions(database)
  val sessionProfiles = SessionProfiles(database)
  val openVPNForwardPorts = OpenVPNForwardPorts(database)
  val interceptModel = InterceptModel()
  val diff = Diff()
  val diffJson = DiffJson()
  val diffBinary = DiffBinary()
  val diffModels = DiffModels(diff, diffBinary, diffJson)
  val fontManager = FontManager(configs)
  val charSetUtility = CharSetUtility(charSets)
  val certCacheManager = CertCacheManager()
  val caFactory = CAFactory()
  val recentProjectsStore = RecentProjectsStore()

  companion object {
    @Volatile private var installed: ModelServices? = null

    fun install(services: ModelServices) {
      check(installed == null) { "ModelServices has already been installed." }
      installed = services
    }

    @JvmStatic
    fun require(): ModelServices =
      checkNotNull(installed) { "ModelServices.install() must be called first." }
  }
}
