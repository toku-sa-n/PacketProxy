/*
 * Copyright 2019 DeNA Co., Ltd.
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
package packetproxy.extensions.securityheaders;

import java.awt.*;
import java.util.*;
import java.util.List;
import javax.swing.*;
import javax.swing.RowSorter.SortKey;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableRowSorter;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import packetproxy.extensions.securityheaders.checks.*;
import packetproxy.http.Http;
import packetproxy.http.HttpHeader;
import packetproxy.model.Extension;
import packetproxy.model.Packet;
import packetproxy.model.Packets;

/**
 * Security Headers Extension for PacketProxy. Analyzes HTTP responses for
 * security header compliance.
 *
 * <p>
 * To add a new security check: 1. Create a new class implementing SecurityCheck
 * interface 2. Add the check to the SECURITY_CHECKS list in this class
 */
public class SecurityHeadersExtension extends Extension {

	// ===== Registered Security Checks =====
	// Add new checks here to extend functionality
	private static final List<SecurityCheck> SECURITY_CHECKS = Arrays.asList(new CspCheck(), new XssProtectionCheck(),
			new HstsCheck(), new ContentTypeCheck(), new CacheControlCheck(), new CookieCheck(), new CorsCheck());

	private JTable table;
	private DefaultTableModel model;
	private TableRowSorter<DefaultTableModel> sorter;
	private Map<String, Integer> endpointMap;
	private Map<String, Packet> packetMap;
	private Map<String, Map<String, SecurityCheckResult>> resultsMap;
	private JTextPane detailArea;
	private JTextPane headerPane;
	private JTextField filterField;
	private List<JCheckBox> methodCheckBoxes;
	private List<JCheckBox> statusCheckBoxes;

	private static final String[] METHOD_OPTIONS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"};
	private static final String[] STATUS_CODE_OPTIONS = {"2xx", "3xx", "4xx", "5xx"};

	public SecurityHeadersExtension() {
		super();
		this.setName("SecurityHeaders");
		this.endpointMap = new HashMap<>();
		this.packetMap = new HashMap<>();
		this.resultsMap = new HashMap<>();
	}

	@Override
	public JComponent createPanel() throws Exception {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(createButtonPanel(), BorderLayout.NORTH);

		initializeTableModel();
		initializeTable();

		JScrollPane tableScrollPane = new JScrollPane(table);
		JSplitPane bottomSplit = createDetailPanes();

		JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScrollPane, bottomSplit);
		mainSplit.setDividerLocation(300);
		panel.add(mainSplit, BorderLayout.CENTER);

		setupSelectionListener();

		return panel;
	}

	// ===== UI Component Creation =====

	private JPanel createButtonPanel() {
		JPanel buttonPanel = new JPanel(new BorderLayout());

		// Left side: buttons
		JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		JButton scanButton = new JButton("Scan History");
		scanButton.addActionListener(e -> scanHistory());
		leftPanel.add(scanButton);

		JButton clearButton = new JButton("Clear");
		clearButton.addActionListener(e -> clearTable());
		leftPanel.add(clearButton);

		buttonPanel.add(leftPanel, BorderLayout.WEST);

		// Right side: filter
		JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));

		// Method filter checkboxes
		filterPanel.add(new JLabel("Method:"));
		methodCheckBoxes = new ArrayList<>();
		for (String method : METHOD_OPTIONS) {
			JCheckBox cb = new JCheckBox(method, true); // default selected
			cb.addActionListener(e -> applyFilter());
			methodCheckBoxes.add(cb);
			filterPanel.add(cb);
		}

		filterPanel.add(Box.createHorizontalStrut(10)); // spacer

		// Status Code filter checkboxes
		filterPanel.add(new JLabel("Server Response:"));
		statusCheckBoxes = new ArrayList<>();
		for (String status : STATUS_CODE_OPTIONS) {
			JCheckBox cb = new JCheckBox(status, true); // default selected
			cb.addActionListener(e -> applyFilter());
			statusCheckBoxes.add(cb);
			filterPanel.add(cb);
		}

		filterPanel.add(Box.createHorizontalStrut(10)); // spacer

		// Text filter
		filterPanel.add(new JLabel("Filter:"));
		filterField = new JTextField(15);
		filterField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				applyFilter();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				applyFilter();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				applyFilter();
			}
		});
		filterPanel.add(filterField);
		buttonPanel.add(filterPanel, BorderLayout.EAST);

		return buttonPanel;
	}

	private void initializeTableModel() {
		// Build columns dynamically from registered checks
		List<String> columns = new ArrayList<>();
		columns.add("Method");
		columns.add("URL");
		columns.add("Server Response");
		for (SecurityCheck check : SECURITY_CHECKS) {
			columns.add(check.getColumnName());
		}

		model = new DefaultTableModel(columns.toArray(new String[0]), 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
	}

	private void initializeTable() {
		table = new JTable(model);
		table.setDefaultRenderer(Object.class, new SecurityHeaderRenderer());

		// Set up TableRowSorter for filtering
		sorter = new TableRowSorter<>(model);
		table.setRowSorter(sorter);

		// Set custom header renderer (left-aligned text, sort icon on right)
		table.getTableHeader().setDefaultRenderer(new HeaderRenderer(table));

		// Set column widths
		table.getColumnModel().getColumn(0).setPreferredWidth(30); // Method
		table.getColumnModel().getColumn(1).setPreferredWidth(300); // URL
		table.getColumnModel().getColumn(2).setPreferredWidth(50); // Code
		// Security check columns
		for (int i = 0; i < SECURITY_CHECKS.size(); i++) {
			table.getColumnModel().getColumn(FIXED_COLUMNS + i).setPreferredWidth(80);
		}

		// Default sort by URL ascending
		SwingUtilities.invokeLater(() -> {
			List<SortKey> sortKeys = new ArrayList<>();
			sortKeys.add(new SortKey(1, SortOrder.ASCENDING)); // URL column
			sorter.setSortKeys(sortKeys);
		});
	}

	private JSplitPane createDetailPanes() {
		headerPane = new JTextPane();
		headerPane.setEditable(false);
		headerPane.setBackground(Color.WHITE);
		JScrollPane headerScrollPane = new JScrollPane(headerPane);

		detailArea = new JTextPane();
		detailArea.setEditable(false);
		detailArea.setBackground(Color.WHITE);
		JScrollPane detailScrollPane = new JScrollPane(detailArea);

		JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, headerScrollPane, detailScrollPane);
		bottomSplit.setResizeWeight(0.5);

		return bottomSplit;
	}

	// ===== Text Styles =====

	private static class TextStyles {
		final SimpleAttributeSet green;
		final SimpleAttributeSet red;
		final SimpleAttributeSet yellow;
		final SimpleAttributeSet black;
		final SimpleAttributeSet bold;

		TextStyles() {
			green = new SimpleAttributeSet();
			StyleConstants.setForeground(green, new Color(0, 128, 0));
			StyleConstants.setBackground(green, new Color(240, 255, 240));

			red = new SimpleAttributeSet();
			StyleConstants.setForeground(red, new Color(200, 0, 0));
			StyleConstants.setBold(red, true);
			StyleConstants.setBackground(red, new Color(255, 240, 240));

			yellow = new SimpleAttributeSet();
			StyleConstants.setForeground(yellow, new Color(220, 130, 0));
			StyleConstants.setBackground(yellow, new Color(255, 255, 240));

			black = new SimpleAttributeSet();
			StyleConstants.setForeground(black, Color.BLACK);

			bold = new SimpleAttributeSet();
			StyleConstants.setBold(bold, true);
			StyleConstants.setForeground(bold, Color.BLACK);
		}
	}

	// ===== Selection Listener =====

	private void setupSelectionListener() {
		table.getSelectionModel().addListSelectionListener(event -> {
			if (event.getValueIsAdjusting())
				return;

			int viewRow = table.getSelectedRow();
			if (viewRow == -1)
				return;

			int modelRow = table.convertRowIndexToModel(viewRow);
			String method = (String) model.getValueAt(modelRow, 0);
			String url = (String) model.getValueAt(modelRow, 1);
			String statusCode = (String) model.getValueAt(modelRow, 2);
			String key = method + " " + url + " " + statusCode;

			Packet p = packetMap.get(key);
			if (p == null)
				return;

			Map<String, SecurityCheckResult> results = resultsMap.get(key);
			if (results == null)
				return;

			try {
				Http http = Http.create(p.getDecodedData());
				HttpHeader header = http.getHeader();
				TextStyles styles = new TextStyles();

				populateHeaderPane(header, results, styles);
				populateIssuesPane(header, results, styles);

			} catch (Exception e) {
				e.printStackTrace();
			}
		});
	}

	private void populateHeaderPane(HttpHeader header, Map<String, SecurityCheckResult> results, TextStyles styles)
			throws Exception {
		StyledDocument doc = headerPane.getStyledDocument();
		headerPane.setText("");

		// Status line
		doc.insertString(doc.getLength(), header.getStatusline() + "\n", styles.bold);

		// All headers with color coding
		byte[] headerBytes = header.toByteArray();
		String rawHeaders = new String(headerBytes, "UTF-8");
		String[] lines = rawHeaders.split("\r\n|\n");

		for (String line : lines) {
			if (line.isEmpty())
				continue;

			// Try segment-based highlighting first
			List<SecurityCheck.HighlightSegment> allSegments = collectHighlightSegments(line, results);

			if (!allSegments.isEmpty()) {
				// Sort segments by start position
				allSegments.sort((a, b) -> Integer.compare(a.getStart(), b.getStart()));
				insertLineWithSegments(doc, line, allSegments, styles);
			} else {
				// Fall back to whole-line highlighting
				SimpleAttributeSet style = getStyleForHeaderLine(line, results, styles);
				doc.insertString(doc.getLength(), line + "\n", style);
			}
		}
	}

	private List<SecurityCheck.HighlightSegment> collectHighlightSegments(String line,
			Map<String, SecurityCheckResult> results) {
		List<SecurityCheck.HighlightSegment> allSegments = new ArrayList<>();

		for (SecurityCheck check : SECURITY_CHECKS) {
			if (!check.matchesHeaderLine(line.toLowerCase()))
				continue;

			SecurityCheckResult result = results.get(check.getName());
			List<SecurityCheck.HighlightSegment> segments = check.getHighlightSegments(line, result);
			allSegments.addAll(segments);
		}

		return allSegments;
	}

	private void insertLineWithSegments(StyledDocument doc, String line, List<SecurityCheck.HighlightSegment> segments,
			TextStyles styles) throws Exception {
		int currentPos = 0;
		int lineLength = line.length();

		for (SecurityCheck.HighlightSegment segment : segments) {
			int start = segment.getStart();
			int end = segment.getEnd();

			// Validate segment bounds
			if (start < 0 || end < 0 || start > lineLength || end > lineLength || start > end) {
				continue;
			}

			// Insert text before this segment (black)
			if (start > currentPos) {
				String beforeText = line.substring(currentPos, start);
				doc.insertString(doc.getLength(), beforeText, styles.black);
			}

			// Insert the segment with appropriate style
			String segmentText = line.substring(start, end);
			SimpleAttributeSet style = getStyleForHighlightType(segment.getType(), styles);
			doc.insertString(doc.getLength(), segmentText, style);
			currentPos = end;
		}

		// Insert remaining text after last segment (black)
		if (currentPos < line.length()) {
			doc.insertString(doc.getLength(), line.substring(currentPos), styles.black);
		}

		doc.insertString(doc.getLength(), "\n", styles.black);
	}

	private SimpleAttributeSet getStyleForHighlightType(SecurityCheck.HighlightType type, TextStyles styles) {
		switch (type) {
			case GREEN :
				return styles.green;
			case RED :
				return styles.red;
			case YELLOW :
				return styles.yellow;
			default :
				return styles.black;
		}
	}

	private SimpleAttributeSet getStyleForHeaderLine(String line, Map<String, SecurityCheckResult> results,
			TextStyles styles) {
		for (SecurityCheck check : SECURITY_CHECKS) {
			SecurityCheckResult result = results.get(check.getName());
			SecurityCheck.HighlightType type = check.getHighlightType(line, result);
			if (type == SecurityCheck.HighlightType.GREEN) {
				return styles.green;
			} else if (type == SecurityCheck.HighlightType.RED) {
				return styles.red;
			}
		}

		// Special handling for Set-Cookie (per-line check)
		String lowerLine = line.toLowerCase();
		if (lowerLine.startsWith("set-cookie:")) {
			return CookieCheck.hasSecureFlag(lowerLine) ? styles.green : styles.red;
		}

		return styles.black;
	}

	private void populateIssuesPane(HttpHeader header, Map<String, SecurityCheckResult> results, TextStyles styles)
			throws Exception {
		StyledDocument doc = detailArea.getStyledDocument();
		detailArea.setText("");

		doc.insertString(doc.getLength(), "Security Check Results\n", styles.bold);
		doc.insertString(doc.getLength(), "=".repeat(40) + "\n\n", styles.black);

		// Display results for each check
		for (SecurityCheck check : SECURITY_CHECKS) {
			SecurityCheckResult result = results.get(check.getName());
			if (result != null) {
				writeCheckResult(doc, check, result, styles);
			}
		}
	}

	private void writeCheckResult(StyledDocument doc, SecurityCheck check, SecurityCheckResult result,
			TextStyles styles) throws Exception {
		doc.insertString(doc.getLength(), check.getName() + ": ", styles.bold);

		if (result.isOk()) {
			doc.insertString(doc.getLength(), "OK\n", styles.green);
			doc.insertString(doc.getLength(), "  " + result.getDisplayValue() + "\n\n", styles.black);
		} else if (result.isWarn()) {
			doc.insertString(doc.getLength(), "WARNING\n", styles.yellow);
			doc.insertString(doc.getLength(), "  " + check.getMissingMessage() + "\n", styles.yellow);
			doc.insertString(doc.getLength(), "  Current: " + result.getDisplayValue() + "\n\n", styles.black);
		} else {
			doc.insertString(doc.getLength(), "FAIL\n", styles.red);
			doc.insertString(doc.getLength(), "  " + check.getMissingMessage() + "\n", styles.red);
			doc.insertString(doc.getLength(), "  Current: " + result.getDisplayValue() + "\n\n", styles.black);
		}
	}

	// ===== Table Operations =====

	private void applyFilter() {
		List<RowFilter<DefaultTableModel, Object>> filters = new ArrayList<>();

		// Method filter (OR between selected methods)
		List<RowFilter<DefaultTableModel, Object>> methodFilters = new ArrayList<>();
		for (JCheckBox cb : methodCheckBoxes) {
			if (cb.isSelected()) {
				methodFilters.add(RowFilter.regexFilter("^" + java.util.regex.Pattern.quote(cb.getText()) + "$", 0));
			}
		}
		if (!methodFilters.isEmpty()) {
			filters.add(RowFilter.orFilter(methodFilters));
		}

		// Status Code filter (OR between selected statuses)
		List<RowFilter<DefaultTableModel, Object>> statusFilters = new ArrayList<>();
		for (JCheckBox cb : statusCheckBoxes) {
			if (cb.isSelected()) {
				String statusPrefix = cb.getText().substring(0, 1); // "2", "3", "4", or "5"
				statusFilters.add(RowFilter.regexFilter("^" + statusPrefix + "\\d{2}$", 2));
			}
		}
		if (!statusFilters.isEmpty()) {
			filters.add(RowFilter.orFilter(statusFilters));
		}

		// Text filter
		String text = filterField.getText().trim();
		if (!text.isEmpty()) {
			filters.add(RowFilter.regexFilter("(?i)" + java.util.regex.Pattern.quote(text)));
		}

		// Apply combined filter (AND between method group, status group, and text)
		if (filters.isEmpty()) {
			sorter.setRowFilter(null);
		} else {
			sorter.setRowFilter(RowFilter.andFilter(filters));
		}
	}

	private void clearTable() {
		SwingUtilities.invokeLater(() -> {
			model.setRowCount(0);
			endpointMap.clear();
			packetMap.clear();
			resultsMap.clear();
			detailArea.setText("");
			headerPane.setText("");
			filterField.setText("");
			methodCheckBoxes.forEach(cb -> cb.setSelected(true));
			statusCheckBoxes.forEach(cb -> cb.setSelected(true));
		});
	}

	private void scanHistory() {
		new Thread(() -> {
			try {
				clearTable();
				List<Packet> packets = Packets.getInstance().queryAll();
				Map<Long, Packet> requestMap = new HashMap<>();

				for (Packet p : packets) {
					if (p.getDirection() == Packet.Direction.CLIENT) {
						requestMap.put(p.getGroup(), p);
					}
				}

				for (Packet p : packets) {
					if (p.getDirection() == Packet.Direction.SERVER) {
						Packet req = requestMap.get(p.getGroup());
						if (req != null) {
							analyzePacket(p, req);
						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}).start();
	}

	// ===== Packet Analysis =====

	private void analyzePacket(Packet resPacket, Packet reqPacket) {
		try {
			Http resHttp = Http.create(resPacket.getDecodedData());
			Http reqHttp = Http.create(reqPacket.getDecodedData());

			String method = reqHttp.getMethod();
			String host = reqHttp.getHeader().getValue("Host").orElse(reqPacket.getServerName());
			String path = reqHttp.getPath();
			String statusCode = resHttp.getStatusCode();

			if (method == null || host == null || path == null || statusCode == null) {
				return;
			}

			String url = (reqPacket.getUseSSL() ? "https://" : "http://") + host + path;
			String endpointKey = method + " " + url + " " + statusCode;

			HttpHeader header = resHttp.getHeader();

			// Run all security checks
			Map<String, Object> context = new HashMap<>();
			Map<String, SecurityCheckResult> results = new LinkedHashMap<>();

			for (SecurityCheck check : SECURITY_CHECKS) {
				SecurityCheckResult result = check.check(header, context);
				results.put(check.getName(), result);
			}

			// Build row data
			List<Object> rowData = new ArrayList<>();
			rowData.add(method);
			rowData.add(url);
			rowData.add(statusCode);
			for (SecurityCheck check : SECURITY_CHECKS) {
				SecurityCheckResult result = results.get(check.getName());
				rowData.add(result != null ? result.getDisplayValue() : "");
			}

			Object[] rowArray = rowData.toArray();

			SwingUtilities.invokeLater(() -> {
				if (endpointMap.containsKey(endpointKey)) {
					int row = endpointMap.get(endpointKey);
					for (int i = 0; i < rowArray.length; i++) {
						model.setValueAt(rowArray[i], row, i);
					}
				} else {
					model.addRow(rowArray);
					endpointMap.put(endpointKey, model.getRowCount() - 1);
				}
				packetMap.put(endpointKey, resPacket);
				resultsMap.put(endpointKey, results);
			});

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// ===== Table Renderer =====

	private static final int FIXED_COLUMNS = 3; // Method, URL, Code
	private static final Color COLOR_FAIL = new Color(200, 0, 0);
	private static final Color COLOR_WARN = new Color(220, 130, 0);
	private static final Color COLOR_OK = new Color(0, 100, 0);
	private static final Color COLOR_FAIL_BG = new Color(255, 240, 240);

	/** Custom header renderer: left-aligned text with sort icon on the right */
	class HeaderRenderer extends JPanel implements TableCellRenderer {
		private final JLabel textLabel;
		private final JLabel iconLabel;
		private final TableCellRenderer defaultRenderer;

		public HeaderRenderer(JTable table) {
			this.defaultRenderer = table.getTableHeader().getDefaultRenderer();
			setLayout(new BorderLayout());
			setOpaque(true);

			textLabel = new JLabel();
			textLabel.setHorizontalAlignment(SwingConstants.LEFT);

			iconLabel = new JLabel();
			iconLabel.setHorizontalAlignment(SwingConstants.RIGHT);

			add(textLabel, BorderLayout.CENTER);
			add(iconLabel, BorderLayout.EAST);
		}

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
				int row, int column) {
			// Get default component to extract styling
			Component defaultComponent = defaultRenderer.getTableCellRendererComponent(table, value, isSelected,
					hasFocus, row, column);

			// Copy background and border from default renderer
			setBackground(defaultComponent.getBackground());
			setForeground(defaultComponent.getForeground());
			setFont(defaultComponent.getFont());
			if (defaultComponent instanceof JComponent) {
				setBorder(((JComponent) defaultComponent).getBorder());
			}

			// Set text
			textLabel.setText(value != null ? value.toString() : "");
			textLabel.setFont(getFont());
			textLabel.setForeground(getForeground());

			// Get sort icon from default renderer
			iconLabel.setIcon(null);
			if (defaultComponent instanceof JLabel) {
				Icon icon = ((JLabel) defaultComponent).getIcon();
				iconLabel.setIcon(icon);
			}

			return this;
		}
	}

	class SecurityHeaderRenderer extends DefaultTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
				int row, int column) {
			Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

			int modelRow = table.convertRowIndexToModel(row);
			String endpointKey = buildEndpointKey(modelRow);
			Map<String, SecurityCheckResult> results = resultsMap.get(endpointKey);

			applyBackgroundColor(c, results, isSelected);
			applyForegroundColor(c, column, results, isSelected);

			return c;
		}

		private String buildEndpointKey(int modelRow) {
			String method = (String) model.getValueAt(modelRow, 0);
			String url = (String) model.getValueAt(modelRow, 1);
			String code = (String) model.getValueAt(modelRow, 2);
			return method + " " + url + " " + code;
		}

		private void applyBackgroundColor(Component c, Map<String, SecurityCheckResult> results, boolean isSelected) {
			if (isSelected)
				return;

			boolean hasFail = results != null && results.values().stream().anyMatch(r -> r.isFail() || r.isWarn());
			c.setBackground(hasFail ? COLOR_FAIL_BG : Color.WHITE);
		}

		private void applyForegroundColor(Component c, int column, Map<String, SecurityCheckResult> results,
				boolean isSelected) {
			if (isSelected) {
				c.setForeground(table.getSelectionForeground());
				return;
			}

			// Fixed columns (Method, URL, Code)
			if (column < FIXED_COLUMNS) {
				c.setForeground(Color.BLACK);
				return;
			}

			// Check columns
			int checkIndex = column - FIXED_COLUMNS;
			if (checkIndex < SECURITY_CHECKS.size() && results != null) {
				SecurityCheck check = SECURITY_CHECKS.get(checkIndex);
				SecurityCheckResult result = results.get(check.getName());
				applyResultStyle(c, result);
			} else {
				c.setForeground(Color.BLACK);
			}
		}

		private void applyResultStyle(Component c, SecurityCheckResult result) {
			if (result == null) {
				c.setForeground(Color.BLACK);
				return;
			}

			if (result.isFail()) {
				c.setForeground(COLOR_FAIL);
				c.setFont(c.getFont().deriveFont(Font.BOLD));
			} else if (result.isWarn()) {
				c.setForeground(COLOR_WARN);
				c.setFont(c.getFont().deriveFont(Font.BOLD));
			} else if (result.isOk()) {
				c.setForeground(COLOR_OK);
			} else {
				c.setForeground(Color.BLACK);
			}
		}
	}
}
