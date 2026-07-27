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
package packetproxy.extensions.endpointoverview

import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.TreePath

object EndpointTreeKeys {
  fun keyForHost(host: String): String = "host|$host"

  fun keyForFolder(host: String, fullPathPrefix: String): String = "folder|$host|$fullPathPrefix"

  fun keyForMethod(host: String, fullPathPrefix: String, method: String): String =
    "method|$host|$fullPathPrefix|$method"

  fun keyForPath(path: TreePath): String? {
    var host: String? = null
    var fullPathPrefix = ""
    var lastKey: String? = null
    for (i in 1 until path.pathCount) {
      val node = path.getPathComponent(i) as? DefaultMutableTreeNode ?: return null
      when (val obj = node.userObject) {
        is EndpointTreeHost -> {
          host = obj.host
          lastKey = keyForHost(obj.host)
        }
        is EndpointTreeFolder -> {
          val currentHost = host ?: return null
          fullPathPrefix = obj.fullPathPrefix
          lastKey = keyForFolder(currentHost, obj.fullPathPrefix)
        }
        is EndpointTreeMethod -> {
          val currentHost = host ?: return null
          lastKey = keyForMethod(currentHost, fullPathPrefix, obj.method)
        }
      }
    }
    return lastKey
  }

  fun findPathByKey(root: DefaultMutableTreeNode, targetKey: String): TreePath? {
    val rootPath = TreePath(root)
    for (i in 0 until root.childCount) {
      val child = root.getChildAt(i) as DefaultMutableTreeNode
      findPathByKey(child, rootPath, null, "", targetKey)?.let {
        return it
      }
    }
    return null
  }

  private fun findPathByKey(
    node: DefaultMutableTreeNode,
    parentPath: TreePath,
    host: String?,
    fullPathPrefix: String,
    targetKey: String,
  ): TreePath? {
    val path = parentPath.pathByAddingChild(node)
    val obj = node.userObject
    val key: String?
    val nextHost: String?
    val nextPrefix: String
    when (obj) {
      is EndpointTreeHost -> {
        key = keyForHost(obj.host)
        nextHost = obj.host
        nextPrefix = ""
      }
      is EndpointTreeFolder -> {
        if (host == null) return null
        key = keyForFolder(host, obj.fullPathPrefix)
        nextHost = host
        nextPrefix = obj.fullPathPrefix
      }
      is EndpointTreeMethod -> {
        if (host == null) return null
        key = keyForMethod(host, fullPathPrefix, obj.method)
        nextHost = host
        nextPrefix = fullPathPrefix
      }
      else -> {
        key = null
        nextHost = host
        nextPrefix = fullPathPrefix
      }
    }
    if (key == targetKey) {
      return path
    }
    for (i in 0 until node.childCount) {
      val child = node.getChildAt(i) as DefaultMutableTreeNode
      findPathByKey(child, path, nextHost, nextPrefix, targetKey)?.let {
        return it
      }
    }
    return null
  }
}
