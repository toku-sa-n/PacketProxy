package packetproxy.common

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.annotations.SerializedName
import packetproxy.model.Database
import packetproxy.model.Filter
import packetproxy.model.Filters
import packetproxy.util.Logging.errWithStackTrace

class FilterIO {
  private class DaoHub {
    @SerializedName("filters") lateinit var filterList: List<Filter>
  }

  @Throws(Exception::class)
  fun getOptions(): String {
    val daoHub = DaoHub()
    daoHub.filterList = Filters.getInstance().queryAll().toMutableList().also { it.reverse() }
    val gson = GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create()
    return gson.toJson(daoHub)
  }

  fun setOptions(json: String) {
    try {
      val daoHub = Gson().fromJson(json, DaoHub::class.java)
      Database.getInstance().dropFilters()
      for (filter in daoHub.filterList) {
        val f = Filter(filter.getName()!!, filter.getFilter()!!)
        Filters.getInstance().create(f)
      }
    } catch (e: Exception) {
      errWithStackTrace(e)
    }
  }
}
