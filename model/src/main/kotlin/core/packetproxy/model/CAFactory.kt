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
package packetproxy.model

import java.nio.file.Paths
import java.util.Comparator.comparing
import java.util.Optional
import java.util.stream.Collectors
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.StandardLocation
import javax.tools.ToolProvider
import packetproxy.model.CAs.CA
import packetproxy.util.errWithStackTrace

class CAFactory {
  // public static void main(String[] args) {
  // CAFactory.queryAll().stream().forEach(ca -> Logging.log(ca));
  // Logging.log("----");
  // CAFactory.find("PacketProxy CA").ifPresent(ca -> Logging.log(ca));
  // CAFactory.find("PacketProxy CA2").ifPresent(ca -> Logging.log(ca));
  // Logging.log("----");
  // CA a = CAFactory.find("PacketProxy CA").get();
  // CA b = CAFactory.find("PacketProxy CA").get();
  // Logging.log(a == b);
  // String c = CAFactory.find("PacketProxy CA2").map(s -> {
  // Logging.log(s); return "ok";}).orElse("Error");
  // Logging.log(c);
  // }

  private val ca_class = packetproxy.model.CAs.CA::class.java
  private val ca_package = "packetproxy.model.CAs"
  private val ca_list = ArrayList<CA>()

  init {
    try {
      val compiler = ToolProvider.getSystemJavaCompiler()
      val fm = compiler.getStandardFileManager(DiagnosticCollector<JavaFileObject>(), null, null)
      val kind =
        object : HashSet<JavaFileObject.Kind>() {
          init {
            add(JavaFileObject.Kind.CLASS)
          }
        }
      for (f in fm.list(StandardLocation.CLASS_PATH, ca_package, kind, false)) {
        val file_path = Paths.get(f.getName())
        val file_name = file_path.fileName
        val ca_class_path =
          ca_package + "." + file_name.toString().replace(Regex("\\.class.*$"), "")
        val klass = Class.forName(ca_class_path)
        if (ca_class.isAssignableFrom(klass) && ca_class != klass) {
          val caKlass = klass.asSubclass(CA::class.java)
          val ca = caKlass.getDeclaredConstructor().newInstance()
          ca_list.add(ca)
        }
        ca_list.stream().sorted(comparing(CA::getName))
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  fun findByUTF8Name(name: String): Optional<CA> =
    ca_list.stream().filter { ca -> ca.getUTF8Name().equals(name, ignoreCase = true) }.findFirst()

  fun find(name: String?): Optional<CA> =
    ca_list.stream().filter { ca -> ca.getName().equals(name, ignoreCase = true) }.findFirst()

  fun queryExportable(): List<CA> =
    ca_list.stream().filter { ca -> ca.isExportable() }.collect(Collectors.toList())

  fun queryAll(): List<CA> = ca_list
}
