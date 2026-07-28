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
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class EndpointTreeKeysTest {
  @Test
  fun keyForPath_returnsStableKeysForHostFolderAndMethod() {
    val summary = createSummary("GET", "https://example.com/api/users", "example.com")
    val root = build(listOf(summary))
    val hostNode = root.getChildAt(0) as DefaultMutableTreeNode
    val apiNode = hostNode.getChildAt(0) as DefaultMutableTreeNode
    val usersNode = apiNode.getChildAt(0) as DefaultMutableTreeNode
    val methodNode = usersNode.getChildAt(0) as DefaultMutableTreeNode

    assertEquals("host|example.com", keyForPath(TreePath(arrayOf(root, hostNode))))
    assertEquals("folder|example.com|/api", keyForPath(TreePath(arrayOf(root, hostNode, apiNode))))
    assertEquals(
      "folder|example.com|/api/users",
      keyForPath(TreePath(arrayOf(root, hostNode, apiNode, usersNode))),
    )
    assertEquals(
      "method|example.com|/api/users|GET",
      keyForPath(TreePath(arrayOf(root, hostNode, apiNode, usersNode, methodNode))),
    )
  }

  @Test
  fun findPathByKey_findsExistingNodesAndReturnsNullForMissing() {
    val summary = createSummary("GET", "https://example.com/api/users", "example.com")
    val root = build(listOf(summary))

    val hostPath = findPathByKey(root, "host|example.com")
    assertNotNull(hostPath)
    val hostNode = hostPath!!.lastPathComponent as DefaultMutableTreeNode
    assertEquals("example.com", (hostNode.userObject as EndpointTreeHost).host)

    val methodPath = findPathByKey(root, "method|example.com|/api/users|GET")
    assertNotNull(methodPath)
    val methodNode = methodPath!!.lastPathComponent as DefaultMutableTreeNode
    assertEquals("GET", (methodNode.userObject as EndpointTreeMethod).method)

    assertNull(findPathByKey(root, "host|other.example.com"))
  }

  private fun createSummary(method: String, url: String, host: String): EndpointSummary {
    return EndpointSummary(method = method, url = url, host = host)
  }
}
