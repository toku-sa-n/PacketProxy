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
package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.beans.PropertyChangeEvent
import java.util.function.Supplier
import packetproxy.common.*
import packetproxy.model.PropertyChangeEventType.SESSION_PROFILES
import packetproxy.model.SessionProfile
import packetproxy.model.SessionProfiles
import packetproxy.util.errWithStackTrace

class GUIOptionSessionProfile
@JvmOverloads
@Throws(Exception::class)
constructor(owner: GUIMain, private val authorizationSupplier: Supplier<String>? = null) :
  GUIOptionComponentBase<SessionProfile>(owner) {
  private val sessionProfiles: SessionProfiles = owner.modelServices.sessionProfiles
  private val tableList = mutableListOf<SessionProfile>()

  init {
    sessionProfiles.addPropertyChangeListener(this)

    val menu = arrayOf(i18nString("Name"), i18nString("Authorization"))
    val menuWidth = intArrayOf(150, 400)

    val tableAction =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          val rowIndex = table.rowAtPoint(e.point)
          if (rowIndex >= 0) {
            table.setRowSelectionInterval(rowIndex, rowIndex)
          }
        }
      }

    val addAction = {
      try {
        val dlg = GUIOptionSessionProfileDialog(owner, authorizationSupplier, sessionProfiles)
        dlg.showDialog()
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    val editAction = {
      try {
        val oldProfile = getSelectedTableContent()
        if (oldProfile != null) {
          val dlg = GUIOptionSessionProfileDialog(owner, authorizationSupplier, sessionProfiles)
          dlg.showDialog(oldProfile)
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    val removeAction = {
      try {
        val selected = getSelectedTableContent()
        if (selected != null) {
          sessionProfiles.delete(selected)
        }
      } catch (e: Exception) {
        errWithStackTrace(e)
      }
    }

    jcomponent =
      createComponent(
        menu,
        menuWidth,
        tableAction,
        { addAction() },
        { editAction() },
        { removeAction() },
      )
    updateImpl()
  }

  fun showManageDialog() {
    try {
      val dlg = GUIOptionSessionProfileDialog(owner, authorizationSupplier, sessionProfiles)
      dlg.showDialog()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun shouldHandlePropertyChange(evt: PropertyChangeEvent): Boolean =
    SESSION_PROFILES.matches(evt)

  override fun addTableContent(value: SessionProfile) {
    tableList.add(value)
    option_model.addRow(
      arrayOf<Any?>(value.name, SessionProfile.formatAuthorizationPreview(value.authorization))
    )
  }

  override fun updateTable(values: List<SessionProfile>) {
    clearTableContents()
    for (profile in values) {
      addTableContent(profile)
    }
  }

  override fun updateImpl() {
    try {
      updateTable(sessionProfiles.queryAll())
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    tableList.clear()
  }

  override fun getSelectedTableContent(): SessionProfile? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int): SessionProfile = tableList[rowIndex]

  fun dispose() {
    sessionProfiles.removePropertyChangeListener(this)
  }
}
