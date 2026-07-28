package packetproxy.model

import com.j256.ormlite.dao.Dao
import com.j256.ormlite.stmt.DeleteBuilder
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import javax.swing.JOptionPane
import packetproxy.model.Database.DatabaseMessage
import packetproxy.util.errWithStackTrace

class ResenderPackets(private val database: Database) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)
  private var dao: Dao<ResenderPacket, Int> = database.createTable(ResenderPacket::class.java, this)

  fun initTable(restore: Boolean) {
    if (restore) {
      if (!isLatestVersion()) {
        recreateTable()
      }
      return
    }
    database.dropTable(ResenderPacket::class.java)
    database.createTable(ResenderPacket::class.java, this)
  }

  fun createResend(resenderPacket: ResenderPacket) {
    dao.create(resenderPacket)
  }

  fun deleteResends(resendsIndex: Int) {
    val deleteBuilder: DeleteBuilder<ResenderPacket, Int> = dao.deleteBuilder()
    deleteBuilder.where().eq("resends_index", resendsIndex)
    dao.delete(deleteBuilder.prepare())
  }

  fun deleteResend(resendsIndex: Int, resendIndex: Int) {
    val deleteBuilder: DeleteBuilder<ResenderPacket, Int> = dao.deleteBuilder()
    deleteBuilder.where().eq("resends_index", resendsIndex).and().eq("resend_index", resendIndex)
    dao.delete(deleteBuilder.prepare())
  }

  fun queryAllOrdered(): List<ResenderPacket> =
    dao.queryBuilder().orderBy("resends_index", true).orderBy("resend_index", true).query()

  fun addPropertyChangeListener(listener: PropertyChangeListener) {
    changes.addPropertyChangeListener(listener)
  }

  fun removePropertyChangeListener(listener: PropertyChangeListener) {
    changes.removePropertyChangeListener(listener)
  }

  fun firePropertyChange(newValue: Any?) {
    changes.firePropertyChange(PropertyChangeEventType.RESENDER_PACKETS.toString(), null, newValue)
  }

  override fun propertyChange(event: PropertyChangeEvent) {
    if (!PropertyChangeEventType.DATABASE_MESSAGE.matches(event)) {
      return
    }
    try {
      when (val message = event.newValue as DatabaseMessage) {
        DatabaseMessage.PAUSE,
        DatabaseMessage.RESUME,
        DatabaseMessage.DISCONNECT_NOW -> {}
        DatabaseMessage.RECONNECT -> {
          dao = database.createTable(ResenderPacket::class.java, this)
          firePropertyChange(message)
        }
        DatabaseMessage.RECREATE -> {
          dao = database.createTable(ResenderPacket::class.java, this)
        }
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }

  private fun isLatestVersion(): Boolean {
    val result =
      dao.queryRaw("SELECT sql FROM sqlite_master WHERE name='resender_packets'").firstResult[0]
    return result ==
      "CREATE TABLE `resender_packets` (`id` INTEGER PRIMARY KEY AUTOINCREMENT , `resends_index` INTEGER , `resend_index` INTEGER , `direction` VARCHAR , `data` BLOB , `listen_port` INTEGER , `client_ip` VARCHAR , `client_port` INTEGER , `server_ip` VARCHAR , `server_port` INTEGER , `server_name` VARCHAR , `use_ssl` BOOLEAN , `encoder_name` VARCHAR , `alpn` VARCHAR , `auto_modified` BOOLEAN , `conn` INTEGER , `group` BIGINT , UNIQUE (`resends_index`,`resend_index`,`direction`) )"
  }

  private fun recreateTable() {
    val option =
      JOptionPane.showConfirmDialog(
        null,
        "resender_packetsテーブルの形式が更新されているため\n現在のテーブルを削除して再起動しても良いですか？",
        "テーブルの更新",
        JOptionPane.YES_NO_OPTION,
        JOptionPane.WARNING_MESSAGE,
      )
    if (option != JOptionPane.YES_OPTION) {
      return
    }
    database.dropTable(ResenderPacket::class.java)
    dao = database.createTable(ResenderPacket::class.java, this)
  }
}
