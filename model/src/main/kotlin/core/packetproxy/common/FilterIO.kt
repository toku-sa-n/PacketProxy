package packetproxy.common

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.annotations.SerializedName
import packetproxy.model.Database
import packetproxy.model.Filter
import packetproxy.model.Filters
import packetproxy.util.errWithStackTrace

class FilterIO(private val database: Database, private val filters: Filters) {
  private class DaoHub {
    @SerializedName("filters") lateinit var filterList: List<Filter>
  }

  @Throws(Exception::class)
  fun getOptions(): String {
    val daoHub = DaoHub()
    daoHub.filterList = filters.queryAll().toMutableList().also { it.reverse() }
    val gson = GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create()
    return gson.toJson(daoHub)
  }

  fun setOptions(json: String) {
    try {
      val daoHub = Gson().fromJson(json, DaoHub::class.java)
      database.dropFilters()
      for (filter in daoHub.filterList) {
        val f = Filter(filter.getName()!!, filter.getFilter()!!)
        filters.create(f)
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
