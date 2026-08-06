package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import packetproxy.common.i18nStringArray
import packetproxy.model.ClientCertificate
import packetproxy.util.errWithStackTrace

class GUIOptionClientCertificate(owner: GUIMain) :
  GUIOptionComponentBase<ClientCertificate>(owner) {
  private val clientCertificates = owner.modelServices.clientCertificates
  private val tableList = mutableListOf<ClientCertificate>()

  init {
    clientCertificates.addPropertyChangeListener(this)
    val tableAction =
      object : MouseAdapter() {
        override fun mouseClicked(e: MouseEvent) {
          try {
            val columnIndex = table.columnAtPoint(e.point)
            val rowIndex = table.rowAtPoint(e.point)
            if (columnIndex == 0) {
              val certificate = getTableContent(rowIndex)
              if (table.getValueAt(rowIndex, 0) as Boolean) certificate.setDisabled()
              else certificate.setEnabled()
              clientCertificates.update(certificate)
            }
            table.setRowSelectionInterval(rowIndex, rowIndex)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        }
      }
    jcomponent =
      createComponent(
        i18nStringArray("Enabled", "Type", "Host", "Subject(CN)", "Issuer"),
        intArrayOf(50, 50, 200, 100, 350),
        tableAction,
        {
          try {
            val certificate = GUIOptionClientCertificateDialog(owner).showDialog()
            if (certificate != null) clientCertificates.create(certificate)
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            val oldCertificate = getSelectedTableContent() ?: return@createComponent
            val certificate = GUIOptionClientCertificateDialog(owner).showDialog(oldCertificate)
            if (certificate != null) {
              clientCertificates.delete(oldCertificate)
              clientCertificates.create(certificate)
            }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
        {
          try {
            getSelectedTableContent()?.let { clientCertificates.delete(it) }
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
      )
    updateImpl()
  }

  fun dispose() {
    clientCertificates.removePropertyChangeListener(this)
  }

  override fun addTableContent(certificate: ClientCertificate) {
    tableList.add(certificate)
    option_model.addRow(
      arrayOf<Any>(
        certificate.isEnabled(),
        certificate.getType()!!.getText(),
        certificate.getServerName(owner.modelServices.database),
        certificate.getSubject() ?: "",
        certificate.getIssuer() ?: "",
      )
    )
  }

  override fun updateTable(certificateList: List<ClientCertificate>) {
    clearTableContents()
    certificateList.forEach(::addTableContent)
  }

  override fun updateImpl() {
    try {
      updateTable(clientCertificates.queryAll())
    } catch (exception: Exception) {
      errWithStackTrace(exception)
    }
  }

  override fun clearTableContents() {
    option_model.rowCount = 0
    tableList.clear()
  }

  override fun getSelectedTableContent(): ClientCertificate? {
    val rowIndex = selectedModelRowOrNull() ?: return null
    return getTableContent(rowIndex)
  }

  override fun getTableContent(rowIndex: Int): ClientCertificate = tableList[rowIndex]
}
