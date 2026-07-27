package packetproxy.gui

import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JFrame
import packetproxy.model.ClientCertificate
import packetproxy.model.ClientCertificates
import packetproxy.util.Logging.errWithStackTrace

class GUIOptionClientCertificate(owner: JFrame) : GUIOptionComponentBase<ClientCertificate>(owner) {
  private val clientCertificates = ClientCertificates.getInstance()
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
        arrayOf("Enabled", "Type", "Host", "Subject(CN)", "Issuer"),
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
            val oldCertificate = getSelectedTableContent()
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
            clientCertificates.delete(getSelectedTableContent())
          } catch (exception: Exception) {
            errWithStackTrace(exception)
          }
        },
      )
    updateImpl()
  }

  override fun addTableContent(certificate: ClientCertificate) {
    tableList.add(certificate)
    option_model.addRow(
      arrayOf<Any>(
        certificate.isEnabled(),
        certificate.getType()!!.getText(),
        certificate.getServerName(),
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

  override fun getSelectedTableContent(): ClientCertificate = getTableContent(table.selectedRow)

  override fun getTableContent(rowIndex: Int): ClientCertificate = tableList[rowIndex]
}
