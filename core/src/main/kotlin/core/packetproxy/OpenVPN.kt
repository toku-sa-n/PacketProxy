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
package packetproxy

import com.github.dockerjava.api.DockerClient
import com.github.dockerjava.api.async.ResultCallback
import com.github.dockerjava.api.command.PullImageResultCallback
import com.github.dockerjava.api.exception.NotFoundException
import com.github.dockerjava.api.exception.NotModifiedException
import com.github.dockerjava.api.model.Bind
import com.github.dockerjava.api.model.Capability
import com.github.dockerjava.api.model.ExposedPort
import com.github.dockerjava.api.model.Frame
import com.github.dockerjava.api.model.HostConfig
import com.github.dockerjava.api.model.PortBinding
import com.github.dockerjava.api.model.Ports
import com.github.dockerjava.api.model.Volume
import com.github.dockerjava.core.DefaultDockerClientConfig
import com.github.dockerjava.core.DockerClientImpl
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient
import java.io.Closeable
import java.io.IOException
import java.time.Duration
import java.util.concurrent.CountDownLatch
import packetproxy.model.OpenVPNForwardPorts
import packetproxy.util.Logging.err
import packetproxy.util.Logging.errWithStackTrace
import packetproxy.util.Logging.log

class OpenVPN private constructor() {
  companion object {
    private var instance: OpenVPN? = null
    private const val imageName = "alekslitvinenk/openvpn"
    private const val containerName = "packetproxy_ovpn"
    private const val volumeName = "packetproxy_ovpn_volume"

    @JvmStatic
    @Throws(Exception::class)
    fun getInstance(): OpenVPN {
      if (instance == null) {
        instance = OpenVPN()
      }
      return instance!!
    }
  }

  private var pulling = false

  private fun getClient(): DockerClient {
    val config = DefaultDockerClientConfig.createDefaultConfigBuilder().build()
    val httpClient =
      ApacheDockerHttpClient.Builder()
        .dockerHost(config.dockerHost)
        .sslConfig(config.sslConfig)
        .maxConnections(100)
        .connectionTimeout(Duration.ofSeconds(30))
        .responseTimeout(Duration.ofSeconds(45))
        .build()
    return DockerClientImpl.getInstance(config, httpClient)
  }

  fun startServer(ip: String, proto: String): Boolean {
    try {
      val client = getClient()
      if (!getImage(client)) {
        return false
      }
      createContainer(client, ip, proto)
      startContainer(client, proto)
      patchContainer(client, ip, proto)
      return true
    } catch (e: Exception) {
      errWithStackTrace(e)
      return false
    }
  }

  fun stopServer() {
    try {
      val client = getClient()
      removeContainer(client)
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  fun getImage(client: DockerClient): Boolean {
    try {
      client.inspectImageCmd(imageName).exec()
      return true
    } catch (_: NotFoundException) {
      if (pulling) {
        log("already pulling image...")
        return false
      }
      log("docker image not found. start pulling...")
      pulling = true
      try {
        val callback = PullImageResultCallback()
        client.pullImageCmd(imageName).exec(callback)
        callback.awaitCompletion()
        log("docker image pull completed")
        return true
      } catch (e: Exception) {
        errWithStackTrace(e)
        return false
      } finally {
        pulling = false
      }
    }
  }

  fun createContainer(client: DockerClient, localIp: String, proto: String) {
    try {
      client.inspectVolumeCmd(volumeName).exec()
    } catch (_: NotFoundException) {
      client.createVolumeCmd().withName(volumeName).exec()
    }

    try {
      client.inspectContainerCmd(containerName).exec()
    } catch (_: NotFoundException) {
      val hostConfig =
        HostConfig()
          .withBinds(Bind(volumeName, Volume("/opt")))
          .withPortBindings(
            Ports(
              PortBinding.parse("0.0.0.0:1194:1194/udp"),
              PortBinding.parse("0.0.0.0:1194:1194/tcp"),
              PortBinding.parse("0.0.0.0:18080:8080/tcp"),
            )
          )
          .withCapAdd(Capability.NET_ADMIN)

      client
        .createContainerCmd(imageName)
        .withName(containerName)
        .withHostConfig(hostConfig)
        .withExposedPorts(ExposedPort(1194))
        .withEnv("HOST_ADDR=$localIp")
        .exec()
    }
  }

  fun startContainer(client: DockerClient, proto: String) {
    val inspect = client.inspectContainerCmd(containerName).exec()
    if (inspect.getState().running == true) {
      log("OpenVPN Server is already running")
      return
    }

    try {
      client.startContainerCmd(containerName).exec()
    } catch (e: NotFoundException) {
      err(e.toString())
    } catch (e: NotModifiedException) {
      log(e.toString())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  fun removeContainer(client: DockerClient) {
    try {
      client.removeContainerCmd(containerName).withForce(true).exec()
    } catch (e: NotFoundException) {
      log(e.toString())
    }
  }

  @Throws(Exception::class)
  fun execCommand(client: DockerClient, command: Array<String>, detach: Boolean = false) {
    val resp =
      client
        .execCreateCmd(containerName)
        .withPrivileged(true)
        .withUser("root")
        .withCmd(*command)
        .exec()

    if (detach) {
      client.execStartCmd(resp.getId()).withDetach(true).exec(ExecResultCallback())
      return
    }

    val callback = ExecResultCallback()
    client.execStartCmd(resp.getId()).exec(callback)
    callback.awaitCompletion()
  }

  fun patchContainer(client: DockerClient, localIp: String, proto: String) {
    try {
      val forwardPorts = OpenVPNForwardPorts.getInstance().queryAll()
      for (forwardPort in forwardPorts) {
        val command =
          "/sbin/iptables -t nat -A PREROUTING -p " +
            forwardPort.getType().toString() +
            " --dport " +
            forwardPort.getFromPort() +
            " -j DNAT --to-destination " +
            localIp +
            ":" +
            forwardPort.getToPort()

        execCommand(client, arrayOf("/bin/sh", "-c", command))
      }

      // change the server config to use inside the volume
      execCommand(
        client,
        arrayOf(
          "/bin/sh",
          "-c",
          "sed -i 's/\\/etc\\/openvpn\\/server\\.conf/\\/opt\\/Dockovpn\\/config\\/server\\.conf/' /opt/Dockovpn/start.sh",
        ),
      )
      when (proto) {
        "TCP" -> {
          execCommand(
            client,
            arrayOf("/bin/sh", "-c", "sed -i s/udp/tcp-server/ /opt/Dockovpn/config/server.conf"),
          )
          execCommand(
            client,
            arrayOf(
              "/bin/sh",
              "-c",
              "find /opt -name \"client.ovpn\" | xargs sed -i s/udp/tcp-client/",
            ),
          )
        }
        "UDP" -> {
          execCommand(
            client,
            arrayOf("/bin/sh", "-c", "sed -i s/tcp-server/udp/ /opt/Dockovpn/config/server.conf"),
          )
          execCommand(
            client,
            arrayOf(
              "/bin/sh",
              "-c",
              "find /opt -name \"client.ovpn\" | xargs sed -i s/tcp-client/udp/",
            ),
          )
        }
      }
      /*
       * restart the server. it is because
       * - dockovpn is start in entrypoint, this means it is difficult to patch in CMD
       * - so it seems to be necessary to patch in docker exec, but it is after docker
       * start(now doing)
       * - after patching, the server should be restarted to reflect the config
       */
      log("OpenVPN Server is restarting...")
      execCommand(client, arrayOf("/bin/sh", "-c", "kill $(pgrep openvpn)"))
      // detach so the long-lived openvpn process does not block the EDT
      execCommand(
        client,
        arrayOf("openvpn", "--config", "/opt/Dockovpn/config/server.conf"),
        detach = true,
      )
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private inner class ExecResultCallback : ResultCallback<Frame> {
    private val started = CountDownLatch(1)
    private val completed = CountDownLatch(1)
    private var stream: Closeable? = null
    private var closed = false

    override fun onStart(stream: Closeable) {
      this.stream = stream
      this.closed = false
      started.countDown()
    }

    override fun onNext(`object`: Frame) {
      // nothing to do
    }

    override fun onError(error: Throwable) {
      if (closed) return
      err(error.toString())
      onComplete()
    }

    override fun onComplete() {
      try {
        close()
      } catch (e: IOException) {
        throw RuntimeException(e)
      }
    }

    @Throws(IOException::class)
    override fun close() {
      if (!closed) {
        closed = true
        try {
          stream?.close()
        } finally {
          completed.countDown()
        }
      }
    }

    @Throws(Exception::class)
    fun awaitCompletion() {
      try {
        completed.await()
        close()
      } catch (e: IOException) {
        errWithStackTrace(e)
      }
    }
  }
}
