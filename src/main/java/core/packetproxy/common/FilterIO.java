package packetproxy.common;

import static packetproxy.util.Logging.errWithStackTrace;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import java.util.Collections;
import java.util.List;
import packetproxy.AppInitializer;
import packetproxy.model.*;
import packetproxy.model.Filter;

public class FilterIO {

	private static class DaoHub {

		@SerializedName(value = "filters")
		List<Filter> filterList;
	}

	public FilterIO() {
	}

	public String getOptions() throws Exception {
		DaoHub daoHub = new DaoHub();

		daoHub.filterList = AppInitializer.getFilters().queryAll();
		Collections.reverse(daoHub.filterList);

		Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
		String json = gson.toJson(daoHub);

		return json;
	}

	public void setOptions(String json) {
		try {

			DaoHub daoHub = new Gson().fromJson(json, DaoHub.class);

			Database.getInstance().dropFilters();

			for (Filter filter : daoHub.filterList) {

				Filter f = new Filter(filter.getName(), filter.getFilter());
				AppInitializer.getFilters().create(f);
			}
		} catch (Exception e) {

			errWithStackTrace(e);
		}
	}
}
