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
package packetproxy.gui;

import static packetproxy.util.Logging.errWithStackTrace;
import static packetproxy.util.Logging.log;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.function.Supplier;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.Scrollable;
import javax.swing.border.LineBorder;
import packetproxy.AppInitializer;
import packetproxy.controller.SinglePacketAttackController;
import packetproxy.http.Http;
import packetproxy.model.Packet;
import packetproxy.util.CharSetUtility;

public class GUIData {

	private JFrame owner;
	private JPanel main_panel;
	private TabSet tabs;
	private JButton resend_button;
	private JButton resend_multiple_button;
	private JButton attack_button;
	private JButton send_to_resender_button;
	private JButton copy_url_body_button;
	private JButton copy_url_button;
	private JButton copy_body_button;
	private JButton diff_orig_button;
	private JButton diff_button;
	private JButton stop_diff_button;
	private CharSetUtility charSetUtility = AppInitializer.getCharSetUtility();
	boolean isDiff = false;
	boolean isOrigColorExists = false;
	int origIndex;
	Color origColor;
	private JComboBox charSetCombo = new JComboBox(charSetUtility.getAvailableCharSetList().toArray());
	private Supplier<byte[]> dataProvider = null;
	private Supplier<byte[]> bodyDataProvider = null;
	private Supplier<byte[]> responseDataProvider = null;

	public GUIData(JFrame owner) {
		this.owner = owner;
	}

	public void setDataProvider(Supplier<byte[]> provider) {
		this.dataProvider = provider;
	}

	public void setBodyDataProvider(Supplier<byte[]> provider) {
		this.bodyDataProvider = provider;
	}

	public void setResponseDataProvider(Supplier<byte[]> provider) {
		this.responseDataProvider = provider;
	}

	public JComponent createPanel() throws Exception {
		createTabsPanel();
		main_panel.add(createButtonPanel());
		return main_panel;
	}

	public JComponent createTabsPanel() throws Exception {
		main_panel = new JPanel();
		main_panel.setLayout(new BoxLayout(main_panel, BoxLayout.Y_AXIS));

		tabs = new TabSet(true, false);

		main_panel.add(tabs.getTabPanel());

		initButtons();
		return main_panel;
	}

	public JComponent createButtonPanel() {
		JPanel diff_panel = new JPanel();
		diff_panel.add(diff_orig_button);
		diff_panel.add(diff_button);
		diff_panel.add(stop_diff_button);
		diff_panel.setBorder(new LineBorder(Color.black, 1, true));
		diff_panel.setLayout(new BoxLayout(diff_panel, BoxLayout.LINE_AXIS));

		JPanel button_panel = new JPanel();
		button_panel.add(charSetCombo);
		button_panel.add(copy_url_body_button);
		button_panel.add(copy_body_button);
		button_panel.add(copy_url_button);
		button_panel.add(resend_button);
		button_panel.add(resend_multiple_button);
		button_panel.add(attack_button);
		button_panel.add(send_to_resender_button);
		button_panel.add(new JLabel("  diff: "));
		button_panel.add(diff_panel);
		button_panel.setLayout(new BoxLayout(button_panel, BoxLayout.LINE_AXIS));

		ScrollableCenteredPanel centered_panel = new ScrollableCenteredPanel();
		centered_panel.add(button_panel);
		return createButtonScrollPane(centered_panel);
	}

	/**
	 * ビューポートが十分に広い場合はボタンを中央寄せし、 狭い場合は横スクロールバーを表示するためのパネル。
	 * getScrollableTracksViewportWidth() でビューポート幅に追従するかを切り替える。
	 */
	private static class ScrollableCenteredPanel extends JPanel implements Scrollable {

		ScrollableCenteredPanel() {
			super(new FlowLayout(FlowLayout.CENTER));
		}

		@Override
		public Dimension getPreferredScrollableViewportSize() {
			return getPreferredSize();
		}

		@Override
		public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
			return 20;
		}

		@Override
		public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
			return 100;
		}

		@Override
		public boolean getScrollableTracksViewportWidth() {
			return getParent() != null && getParent().getWidth() >= getPreferredSize().width;
		}

		@Override
		public boolean getScrollableTracksViewportHeight() {
			return true;
		}
	}

	private byte[] getActiveData() {
		if (dataProvider != null) {
			return dataProvider.get();
		}
		int index = tabs.getSelectedIndex();
		if (index == 0) {
			return tabs.getRaw().getData();
		} else if (index == 1) {
			return tabs.getBinary().getData();
		}
		return null;
	}

	private void initButtons() throws Exception {
		copy_url_body_button = new JButton("copy Method+URL+Body");
		copy_url_body_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				try {

					byte[] data = getActiveData();
					if (data == null || data.length == 0)
						return;
					int id = AppInitializer.getGuiMain().getGuiHistory().getSelectedPacketId();
					Packet packet = AppInitializer.getPackets().query(id);
					Http http = Http.create(data);
					String copyData = http.getMethod() + "\t" + http.getURL(packet.getServerPort(), packet.getUseSSL())
							+ "\t" + new String(http.getBody(), "UTF-8");
					Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
					StringSelection selection = new StringSelection(copyData);
					clipboard.setContents(selection, selection);
				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});

		copy_body_button = new JButton("copy Body");
		copy_body_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					byte[] data = resolveDataForCopyBody();
					if (data == null || data.length == 0)
						return;
					Http http = Http.create(data);
					String body = new String(http.getBody(), "UTF-8");
					Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
					StringSelection selection = new StringSelection(body);
					clipboard.setContents(selection, selection);
				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});
		copy_body_button.setAlignmentX(0.5f);

		copy_url_button = new JButton("copy URL");
		copy_url_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					byte[] data = getActiveData();
					if (data == null || data.length == 0)
						return;
					int id = AppInitializer.getGuiMain().getGuiHistory().getSelectedPacketId();
					Packet packet = AppInitializer.getPackets().query(id);
					Http http = Http.create(data);
					String url = http.getURL(packet.getServerPort(), packet.getUseSSL());
					Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
					StringSelection selection = new StringSelection(url);
					clipboard.setContents(selection, selection);

				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});
		copy_url_button.setAlignmentX(0.5f);

		resend_button = new JButton("send");
		resend_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					byte[] data = getActiveData();
					if (data != null && data.length > 0) {

						int id = AppInitializer.getGuiMain().getGuiHistory().getSelectedPacketId();
						Packet packet = AppInitializer.getPackets().query(id);
						AppInitializer.getInterceptController().getResendController()
								.resend(packet.getOneShotPacket(data));
						packet.setResend();
						AppInitializer.getPackets().update(packet);
						AppInitializer.getGuiMain().getGuiHistory().updateRequestOne(id);
					}
				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});
		resend_button.setAlignmentX(0.5f);

		resend_multiple_button = new JButton("send x 20");
		resend_multiple_button.setAlignmentX(0.5f);
		resend_multiple_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					byte[] data = getActiveData();
					if (data != null && data.length > 0) {

						int id = AppInitializer.getGuiMain().getGuiHistory().getSelectedPacketId();
						Packet packet = AppInitializer.getPackets().query(id);
						AppInitializer.getInterceptController().getResendController()
								.resend(packet.getOneShotPacket(data), 20);
						packet.setResend();
						AppInitializer.getPackets().update(packet);
						AppInitializer.getGuiMain().getGuiHistory().updateRequestOne(id);
					}
				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});

		attack_button = new JButton("send x 20 (single-packet attack)");
		attack_button.setAlignmentX(0.5f);
		attack_button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					byte[] data = getActiveData();
					if (data != null && data.length > 0) {
						int id = AppInitializer.getGuiMain().getGuiHistory().getSelectedPacketId();
						Packet packet = AppInitializer.getPackets().query(id);
						new SinglePacketAttackController(packet.getOneShotPacket(data)).attack(20);
						packet.setResend();
						AppInitializer.getPackets().update(packet);
						AppInitializer.getGuiMain().getGuiHistory().updateRequestOne(id);
					}
				} catch (Exception e1) {
					errWithStackTrace(e1);
				}
			}
		});

		send_to_resender_button = new JButton("send to Resender");
		send_to_resender_button.setAlignmentX(0.5f);
		send_to_resender_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				try {

					byte[] data = getActiveData();
					if (data != null && data.length > 0) {

						int id = AppInitializer.getGuiMain().getGuiHistory().getSelectedPacketId();
						Packet packet = AppInitializer.getPackets().query(id);
						packet.setResend();
						AppInitializer.getPackets().update(packet);
						AppInitializer.getGuiMain().getGuiResender().addResends(packet.getOneShotPacket(data));
						AppInitializer.getGuiMain().getGuiHistory().updateRequestOne(id);
					}
				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});

		stop_diff_button = new JButton("stop diff");
		stop_diff_button.setAlignmentX(0.5f);
		stop_diff_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					if (isDiff) {

						AppInitializer.getDiff().clearAsOriginal();
						AppInitializer.getDiffBinary().clearAsOriginal();
						AppInitializer.getDiffJson().clearAsOriginal();
						if (isOrigColorExists) {

							isOrigColorExists = false;
							AppInitializer.getGuiMain().getGuiHistory().addCustomColoring(origIndex,
									new Color(0xb0, 0xb0, 0xb0)); // Gray
						} else {

							AppInitializer.getGuiMain().getGuiHistory().addCustomColoring(origIndex, Color.WHITE);
						}
						isDiff = false;
					}
				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});

		diff_button = new JButton("diff!!");
		diff_button.setAlignmentX(0.5f);
		diff_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					byte[] data = resolveDataForDiff();
					if (data == null)
						return;
					AppInitializer.getDiff().markAsTarget(data);
					AppInitializer.getDiffBinary().markAsTarget(data);
					AppInitializer.getDiffJson().markAsTarget(data);
					GUIDiffDialogParent dlg = new GUIDiffDialogParent(owner);
					dlg.showDialog();
				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});

		diff_orig_button = new JButton("mark as orig");
		diff_orig_button.setAlignmentX(0.5f);
		diff_orig_button.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {

					byte[] data = resolveDataForDiff();
					if (data == null)
						return;
					if (isDiff) {

						AppInitializer.getDiff().clearAsOriginal();
						AppInitializer.getDiffBinary().clearAsOriginal();
						AppInitializer.getDiffJson().clearAsOriginal();
						if (isOrigColorExists) {

							isOrigColorExists = false;
							AppInitializer.getGuiMain().getGuiHistory().addCustomColoring(origIndex, origColor);
						} else {

							AppInitializer.getGuiMain().getGuiHistory().addCustomColoring(origIndex, Color.WHITE);
						}
					}
					isDiff = true;
					AppInitializer.getDiff().markAsOriginal(data);
					AppInitializer.getDiffBinary().markAsOriginal(data);
					AppInitializer.getDiffJson().markAsOriginal(data);
					if (AppInitializer.getGuiMain().getGuiHistory().containsColor()) {

						origColor = AppInitializer.getGuiMain().getGuiHistory().getColor();
						isOrigColorExists = true;
					}
					origIndex = AppInitializer.getGuiMain().getGuiHistory().getSelectedIndex();
					AppInitializer.getGuiMain().getGuiHistory()
							.addCustomColoringToCursorPos(new Color(0xb0, 0xb0, 0xb0)); // Gray
					log("Diff: original text was saved!");
				} catch (Exception e1) {

					errWithStackTrace(e1);
				}
			}
		});

		charSetCombo.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				charSetUtility.setCharSet((String) charSetCombo.getSelectedItem());
				try {

					AppInitializer.getGuiMain().getGuiHistory().getGuiPacket().update();
				} catch (Exception e2) {
					errWithStackTrace(e2);
				}
			}
		});
		charSetCombo.setMaximumSize(new Dimension(150, charSetCombo.getMaximumSize().height));

		charSetCombo.addMouseListener(new MouseAdapter() {

			@Override
			public void mousePressed(MouseEvent e) {
				super.mousePressed(e);
				updateCharSetCombo();
			}
		});

		charSetCombo.setSelectedItem(charSetUtility.getCharSetForGUIComponent());
	}

	public void updateCharSetCombo() {
		charSetCombo.removeAllItems();
		for (String charSetName : charSetUtility.getAvailableCharSetList()) {
			charSetCombo.addItem(charSetName);
		}
		String charSetName = AppInitializer.getCharSetUtility().getCharSetForGUIComponent();
		if (charSetUtility.getAvailableCharSetList().contains(charSetName)) {
			charSetCombo.setSelectedItem(charSetName);
		} else {
			charSetCombo.setSelectedIndex(0);
		}
	}

	static JScrollPane createButtonScrollPane(JPanel buttonPanel) {
		JScrollPane scrollPane = new JScrollPane(buttonPanel, ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED) {
			@Override
			public Dimension getPreferredSize() {
				Dimension d = super.getPreferredSize();
				JScrollBar hBar = getHorizontalScrollBar();
				// スクロールバーが表示されている場合のみ高さを加算することで、
				// 非表示時の余分なスペースを排除しつつ、表示時はレイアウトを押し下げて領域を確保する
				if (hBar != null && hBar.isVisible()) {
					d.height += hBar.getPreferredSize().height;
				}
				return d;
			}
		};
		scrollPane.setBorder(null);
		scrollPane.getViewport().addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				scrollPane.revalidate();
				scrollPane.repaint();
			}
		});
		return scrollPane;
	}

	private void update() {
	}

	public void setData(byte[] data) {
		tabs.setData(data);
		update();
	}

	public byte[] getData() {
		if (tabs.getData() == null) {
			return new byte[]{};
		}
		try {

			return tabs.getData();
		} catch (Exception e) {

			errWithStackTrace(e);
		}
		return new byte[]{};
	}

	/**
	 * マージ行（Request+Response両方ある行）の場合はどちらのBodyをコピーするか
	 * ユーザに選択させる。単一パケット行の場合はRequestデータをそのまま返す。 ダイアログでキャンセルされた場合は null を返す。
	 */
	private byte[] resolveDataForCopyBody() throws Exception {
		if (!AppInitializer.getGuiMain().getGuiHistory().isSelectedRowMerged()) {
			return bodyDataProvider != null ? bodyDataProvider.get() : getActiveData();
		}
		// macOS の JOptionPane はボタンを右から左に描画するため、
		// 視覚的に左から「Request | Response」の順にするには逆順で定義する。
		String[] options = {"Response", "Request"};
		int choice = JOptionPane.showOptionDialog(owner, "Which body do you want to copy?", "Select Copy Target",
				JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, null);
		if (choice == JOptionPane.CLOSED_OPTION)
			return null;
		if (choice == 0)
			return responseDataProvider != null ? responseDataProvider.get() : null;
		return bodyDataProvider != null ? bodyDataProvider.get() : getActiveData();
	}

	/**
	 * マージ行（Request+Response両方ある行）の場合はどちらのデータをDiffに使うか
	 * ユーザに選択させる。単一パケット行の場合はRequestデータをそのまま返す。 ダイアログでキャンセルされた場合は null を返す。
	 */
	private byte[] resolveDataForDiff() throws Exception {
		if (!AppInitializer.getGuiMain().getGuiHistory().isSelectedRowMerged()) {
			return tabs.getRaw().getData();
		}
		// macOS の JOptionPane はボタンを右から左に描画するため、
		// 視覚的に左から「Request | Response」の順にするには逆順で定義する。
		String[] options = {"Response", "Request"};
		int choice = JOptionPane.showOptionDialog(owner, "Which data do you want to use for Diff?",
				"Select Diff Target", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, null);
		if (choice == JOptionPane.CLOSED_OPTION)
			return null;
		if (choice == 0)
			return AppInitializer.getGuiMain().getGuiHistory().getGuiPacket().getResponsePacket().getReceivedData();
		return tabs.getRaw().getData();
	}
}
