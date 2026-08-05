package packetproxy.model

import com.j256.ormlite.dao.Dao
import com.j256.ormlite.stmt.DeleteBuilder
import java.beans.PropertyChangeEvent
import java.beans.PropertyChangeListener
import java.beans.PropertyChangeSupport
import packetproxy.model.Database.DatabaseMessage
import packetproxy.util.errWithStackTrace

class ResenderPackets(private val database: Database) : PropertyChangeListener {
  private val changes = PropertyChangeSupport(this)
  private var dao: Dao<ResenderPacket, Int> = database.createTable(ResenderPacket::class.java, this)

  fun initTable(restore: Boolean) {
    if (restore) {
      SchemaMigrator.ensureCompatible(database, dao, "resender_packets") {
        database.dropTable(ResenderPacket::class.java)
        dao = database.createTable(ResenderPacket::class.java, this)
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
}
