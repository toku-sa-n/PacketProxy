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

import java.awt.Dimension
import java.util.function.Supplier
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JTextField
import packetproxy.common.*
import packetproxy.model.SessionProfile
import packetproxy.model.SessionProfiles
import packetproxy.util.errWithStackTrace

class GUIOptionSessionProfileDialog(
  private val frameOwner: GUIMain,
  private val authorizationSupplier: Supplier<String>?,
  private val sessionProfiles: SessionProfiles,
) : JDialog(frameOwner) {
  private val buttonCancel = JButton(i18nString("Cancel"))
  private val buttonSet = JButton(i18nString("Save"))
  private val nameField = JTextField()
  private val authorizationField = JTextField()

  private var profile: SessionProfile? = null
  private var editingId: Int? = null

  init {
    buildDialog()
  }

  fun showDialog(): SessionProfile? {
    editingId = null
    profile = null
    nameField.text = ""
    authorizationField.text = ""
    isModal = true
    isVisible = true
    return profile
  }

  fun showDialog(initialAuthorization: String?): SessionProfile? {
    editingId = null
    profile = null
    nameField.text = ""
    authorizationField.text = initialAuthorization ?: ""
    isModal = true
    isVisible = true
    return profile
  }

  fun showDialog(preset: SessionProfile): SessionProfile? {
    editingId = preset.id
    profile = null
    nameField.text = preset.name
    authorizationField.text = preset.authorization ?: ""
    isModal = true
    isVisible = true
    return profile
  }

  private fun labelAndObject(labelName: String, objectComponent: JComponent): JComponent {
    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.X_AXIS)
    val label = JLabel(labelName)
    label.preferredSize = Dimension(240, label.maximumSize.height)
    panel.add(label)
    objectComponent.maximumSize = Dimension(Short.MAX_VALUE.toInt(), label.maximumSize.height * 2)
    panel.add(objectComponent)
    return panel
  }

  private fun buttons(): JComponent {
    val panelButton = JPanel()
    panelButton.layout = BoxLayout(panelButton, BoxLayout.X_AXIS)
    panelButton.maximumSize = Dimension(Short.MAX_VALUE.toInt(), buttonSet.maximumSize.height)
    panelButton.add(buttonCancel)
    panelButton.add(buttonSet)
    return panelButton
  }

  private fun buildDialog() {
    title = i18nString("Session Profile")
    val rect = frameOwner.bounds
    val height = 220
    val width = 800
    setBounds(
      rect.x + rect.width / 2 - width / 2,
      rect.y + rect.height / 2 - height / 2,
      width,
      height,
    )

    val panel = JPanel()
    panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
    panel.add(labelAndObject(i18nString("Name:"), nameField))
    panel.add(labelAndObject(i18nString("Authorization:"), authorizationField))

    if (authorizationSupplier != null) {
      val importButton = JButton(i18nString("Import from current request"))
      importButton.addActionListener { importAuthorizationFromRequest() }
      panel.add(importButton)
    }

    panel.add(buttons())
    contentPane.add(panel)

    buttonCancel.addActionListener {
      profile = null
      dispose()
    }

    buttonSet.addActionListener { saveProfile() }
  }

  private fun importAuthorizationFromRequest() {
    try {
      val authorization = authorizationSupplier?.get()
      if (authorization.isNullOrEmpty()) {
        JOptionPane.showMessageDialog(
          frameOwner,
          i18nString("No Authorization header found in the current request."),
          i18nString("Message"),
          JOptionPane.INFORMATION_MESSAGE,
        )
        return
      }
      authorizationField.text = authorization
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun saveProfile() {
    val name = nameField.text.trim()
    if (name.isEmpty()) {
      JOptionPane.showMessageDialog(
        frameOwner,
        i18nString("Name is required."),
        i18nString("Message"),
        JOptionPane.INFORMATION_MESSAGE,
      )
      return
    }

    try {
      val profiles = sessionProfiles
      val authorization = authorizationField.text
      val existing = profiles.queryByName(name)
      val isConflict = existing != null && (editingId == null || existing.id != editingId)

      if (isConflict) {
        val option =
          JOptionPane.showConfirmDialog(
            frameOwner,
            i18nString("A session profile named \"%s\" already exists. Overwrite?", name),
            i18nString("Message"),
            JOptionPane.YES_NO_OPTION,
          )
        if (option != JOptionPane.YES_OPTION) {
          return
        }
        existing.authorization = authorization
        profiles.update(existing)
        if (editingId != null && editingId != existing.id) {
          profiles.delete(profiles.query(editingId!!)!!)
        }
        profile = existing
        dispose()
        return
      }

      if (editingId != null) {
        val current = profiles.query(editingId!!)!!
        current.name = name
        current.authorization = authorization
        profiles.update(current)
        profile = current
      } else {
        val newProfile = SessionProfile(name, authorization)
        profiles.create(newProfile)
        profile = newProfile
      }
      dispose()
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
