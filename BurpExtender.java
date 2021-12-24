package burp;

import javax.swing.JScrollPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.JButton;
import javax.swing.JCheckBox;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Set;
import java.util.Date;
import java.io.FileOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.util.Map;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener,IExtensionStateListener {
	public IBurpExtenderCallbacks extCallbacks;
	public IExtensionHelpers extHelpers;

	public JPanel regexLoggerPanel;

	private JTextField hostTextField;
	private JTextField logDirTextField;
	private JTextField toolsTextField;
	private JTextField mimeTypesTextField;
	
	private String hostRegex;
	private String infoRegexs;
	private String logDir;
	private String[] tools;
	private String[] mimeTypes;

	private String logSuffix = ".txt";
	private String defaultHostRegex = "127\\.0\\.0\\.1";
	private String defaultInfoRegexs = "phone:([01][\\d]{2}[ -]?[\\d]{4}[ -]?[\\d]{4})"+"\n"
			+"email:[a-zA-Z0-9][-a-zA-Z0-9_\\.]+@(?:[a-zA-Z0-9][-a-zA-Z0-9]+\\.)+[a-z]+" + "\n"
			+ "ipurl:https?://[0-9\\.]+(?::[0-9]+)?/?[a-zA-Z0-9/_%-]*" + "\n"
			+ "domainurl:https?://(?:[a-zA-Z0-9]+\\.)+[a-zA-Z]+(?::[0-9]+)?/?[a-zA-Z0-9/_%-]*";
	private String defaultTools = "proxy spider";
	private String defaultMimeTypes = "html script text json";
	private String defaultLogDir;

	private boolean enabled = false;
	private boolean enableLogUrl = false;
	private Pattern hostPattern;
	private Map<FileOutputStream, Pattern> logFilesPattern = new HashMap<FileOutputStream, Pattern>();

	private String separator = System.getProperty("file.separator");
	private String usrHome = System.getProperty("user.home");
	private String osInfo = System.getProperty("os.name");

	private PrintWriter stdout;
	private PrintWriter stderr;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		extCallbacks = callbacks;
		extHelpers = extCallbacks.getHelpers();
		extCallbacks.setExtensionName("regexLogger");
		//register ourselves as an HTTP listener
		extCallbacks.registerHttpListener(this);
		//extCallbacks.removeHttpListener(this);
		extCallbacks.registerExtensionStateListener(this);
		
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);
		defaultLogDir = getLogDir();
		// new panel
		stdout.println("============================\n"
				+ "    RegexLogger\n"
				+ "    Author:h4cnull\n"
				+ "    Github:https://github.com/h4cnull\n"
				+ "============================\n"
				+ "[+]RegexLogger was loaded");
		regexLoggerPanel = new JPanel(null);

		JLabel hostRegexLabel = new JLabel("host\u6B63\u5219");
		hostRegexLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		hostRegexLabel.setBounds(31, 25, 70, 29);
		regexLoggerPanel.add(hostRegexLabel);

		hostTextField = new JTextField();
		hostTextField.setText(defaultHostRegex);
		hostTextField.setBounds(111, 25, 400, 29);
		regexLoggerPanel.add(hostTextField);

		JLabel hostRegexLabelInfo = new JLabel(
				"\u7B5B\u9009\u5339\u914Dhost\u6B63\u5219\u8868\u8FBE\u5F0F\u7684\u54CD\u5E94");
		hostRegexLabelInfo.setBounds(289, 25, 201, 29);
		regexLoggerPanel.add(hostRegexLabelInfo);

		JLabel logDirLabel = new JLabel("\u4FDD\u5B58\u76EE\u5F55");
		logDirLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		logDirLabel.setBounds(31, 64, 70, 27);
		regexLoggerPanel.add(logDirLabel);

		logDirTextField = new JTextField();
		logDirTextField.setText(defaultLogDir);
		logDirTextField.setColumns(10);
		logDirTextField.setBounds(111, 64, 400, 29);
		regexLoggerPanel.add(logDirTextField);

		JLabel regexTextAreaLabel = new JLabel("\u7B5B\u9009\u6B63\u5219");
		regexTextAreaLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		regexTextAreaLabel.setBounds(31, 101, 70, 29);
		regexLoggerPanel.add(regexTextAreaLabel);

		JTextArea regexTextArea = new JTextArea();
		//regexTextArea.setBounds(111, 103, 400, 163);
		regexTextArea.setText(defaultInfoRegexs);
		JScrollPane scroll = new JScrollPane(regexTextArea);
		scroll.setBounds(111, 103, 400, 163);
		regexLoggerPanel.add(scroll);

		JTextArea regexTextAreaInfo = new JTextArea();
		regexTextAreaInfo.setOpaque(false);
		regexTextAreaInfo.setBackground(new Color(0, 0, 0, 0));
		regexTextAreaInfo.setBorder(null);
		regexTextAreaInfo.setLineWrap(true);
		regexTextAreaInfo.setEditable(false);
		regexTextAreaInfo.setText(
				"host\u6B63\u5219\u7528\u6765\u7B5B\u9009\u5339\u914Dhost\u7684\u54CD\u5E94\u3002\r\n\r\n\u7B5B\u9009\u6B63\u5219\u793A\u4F8B\uFF1A\r\nnumber:\\d{11} \r\nstring:[a-z]{5}\r\n\r\n\u7B5B\u900911\u4F4D\u6570\u5B57\u5230number.txt\u4E2D\r\n\u540C\u65F6\u7B5B\u9009\u957F\u5EA6\u4E3A5\u7684\u5B57\u7B26\u4E32\u5230string.txt\u4E2D\r\n\r\nBurp Tool \u7B5B\u9009\u9700log\u7684Tool(\u7A7A\u683C\u5206\u9694)\r\nMIME Type \u7B5B\u9009\u7B26\u5408mime type\u7C7B\u578B\u7684\u54CD\u5E94(\u7A7A\u683C\u5206\u9694)\r\n(\u6CE8\uFF1A\u4FEE\u6539\u6B63\u5219\u540E\u9700\u8981\u91CD\u65B0\u542F\u7528\u63D2\u4EF6\u4EE5\u751F\u6548)");
		regexTextAreaInfo.setBounds(521, 25, 353, 280);
		regexLoggerPanel.add(regexTextAreaInfo);

		toolsTextField = new JTextField();
		toolsTextField.setText(defaultTools);
		toolsTextField.setColumns(10);
		toolsTextField.setBounds(181, 276, 93, 29);
		regexLoggerPanel.add(toolsTextField);

		mimeTypesTextField = new JTextField();
		mimeTypesTextField.setText(defaultMimeTypes);
		mimeTypesTextField.setColumns(10);
		mimeTypesTextField.setBounds(364, 276, 147, 29);
		regexLoggerPanel.add(mimeTypesTextField);

		JLabel burpToolLabel = new JLabel("Burp Tool");
		burpToolLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		burpToolLabel.setBounds(101, 276, 70, 29);
		regexLoggerPanel.add(burpToolLabel);

		JLabel mimeTypeLabel = new JLabel("MIME Type");
		mimeTypeLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		mimeTypeLabel.setBounds(284, 276, 70, 29);
		regexLoggerPanel.add(mimeTypeLabel);

		JCheckBox enableLogUrlCheckBox = new JCheckBox("\u8BB0\u5F55url");
		enableLogUrlCheckBox.setBounds(347, 344, 76, 21);
		regexLoggerPanel.add(enableLogUrlCheckBox);
		enableLogUrlCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				if (enableLogUrlCheckBox.isSelected()) {
					enableLogUrl = true;
					stdout.println("[+]regexLogger log url enabled");
				} else {
					enableLogUrl = false;
					stdout.println("[+]regexLogger log url disabled");
				}
			}
		});
		
		JButton resettingButton = new JButton("\u91CD\u7F6E\u8BBE\u7F6E");
		resettingButton.setBounds(430, 315, 81, 23);
		regexLoggerPanel.add(resettingButton);
		resettingButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				hostRegex = defaultHostRegex;
				infoRegexs = defaultInfoRegexs;
				tools = defaultTools.toLowerCase().split(" ");
				mimeTypes = defaultMimeTypes.toLowerCase().split(" ");
				logDir = defaultLogDir;
				hostTextField.setText(defaultHostRegex);
				logDirTextField.setText(defaultLogDir);
				regexTextArea.setText(defaultInfoRegexs);
				toolsTextField.setText(defaultTools);
				mimeTypesTextField.setText(defaultMimeTypes);
				enableLogUrl = false;
				enableLogUrlCheckBox.setSelected(false);
			}
		});

		JButton newlogDirButton = new JButton("\u65B0\u4FDD\u5B58\u76EE\u5F55");
		newlogDirButton.setBounds(323, 315, 93, 23);
		regexLoggerPanel.add(newlogDirButton);
		newlogDirButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				logDir = getLogDir();
				logDirTextField.setText(logDir);
			}
		});
		
		JCheckBox enableCheckBox = new JCheckBox("\u542F\u7528");
		enableCheckBox.setBounds(453, 344, 57, 21);
		regexLoggerPanel.add(enableCheckBox);
		
		enableCheckBox.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent event) {
				if (enableCheckBox.isSelected()) {
					stdout.println("[+]regexLogger is enabled");
					enabled = true;
					hostRegex = hostTextField.getText();
					logDir = logDirTextField.getText();
					infoRegexs = regexTextArea.getText();
					tools = toolsTextField.getText().toLowerCase().split(" ");
					mimeTypes = mimeTypesTextField.getText().toLowerCase().split(" ");
					CloseCleanLogFileOutputStreams();
					try {
						hostPattern = Pattern.compile(hostRegex);
						stdout.println("[+]regexLogger set host Pattern success");
					} catch (Exception e) {
						stdout.println("[+]regexLogger set host Pattern failed!");
						stderr.println("[!]regexLogger wrong format host regex:\n" + e.toString());
					}
					try {
						File dir = new File(logDir);
						if (!dir.exists() && !dir.isDirectory()) {
							dir.mkdirs();
							stdout.println("[+]regexLogger create log dir: " + logDir);
						}
					} catch (Exception e) {
						stderr.println("[!]regexLogger cannot create log dir:\n" + e.toString());
					}
					String[] lines = infoRegexs.split("\n");
					for (int i = 0; i < lines.length; i++) {
						// byte[] b = lines[i].getBytes();
						// stdout.println(b[b.length-1]);
						try {
							int splitIndex = lines[i].indexOf(':');
							String fileName = logDir + separator + lines[i].substring(0, splitIndex) + logSuffix;
							String regexStr = lines[i].substring(splitIndex + 1);
							Pattern p = Pattern.compile(regexStr);
							FileOutputStream file = new FileOutputStream(fileName, true);
							logFilesPattern.put(file, p);
							stdout.println("[+]regexLogger add regex success: " + fileName + " " + regexStr);
						} catch (Exception e) {
							stderr.println("[!]regexLogger cannot new file and regex pattern by " + lines[i] + ": "
									+ e.toString());
						}
					}
				} else {
					stdout.println("[+]regexLogger is disabled");
					enabled = false;
					hostPattern = null;
					CloseCleanLogFileOutputStreams();
				}
			}
		});

		extCallbacks.customizeUiComponent(regexLoggerPanel);
		extCallbacks.addSuiteTab(BurpExtender.this);
	}

	/* Tab caption */
	@Override
	public String getTabCaption() {
		return "regexLogger";
	}

	/* Java component to return to Burp */
	@Override
	public Component getUiComponent() {
		return regexLoggerPanel;
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// only process responses
		if (!messageIsRequest && enabled && hostPattern != null) {
			String tool = extCallbacks.getToolName(toolFlag).toLowerCase();
			String host = extHelpers.analyzeRequest(messageInfo).getUrl().getHost();
			Matcher m = hostPattern.matcher(host);
			if (Arrays.asList(tools).contains(tool) && m.find()) {
				byte[] rsp = messageInfo.getResponse();
				IResponseInfo rspInfo = extHelpers.analyzeResponse(rsp);
				String type = rspInfo.getStatedMimeType().toLowerCase();
				if (Arrays.asList(mimeTypes).contains(type)) {
					synchronized (logFilesPattern) {
						String url = extHelpers.analyzeRequest(messageInfo).getUrl().toString();
						//stdout.println("true " + host + " " + tool + " " + type + " " + url);
						int bodyBegins = rspInfo.getBodyOffset();
						String bodyData = new String(Arrays.copyOfRange(rsp, bodyBegins, rsp.length));
						for (FileOutputStream f : logFilesPattern.keySet()) {
							try{
								FileDescriptor fd = f.getFD();
								Pattern p = logFilesPattern.get(f);
								Matcher match = p.matcher(bodyData);
								while (match.find()) {
									try {
										if (enableLogUrl) {
											f.write((match.group(0) + "     " + url + "\n").getBytes());
										} else {
											f.write((match.group(0) + "\n").getBytes());
										}
									} catch (Exception e) {
										stderr.println("[!]regexLogger log regex result error: " + e.getMessage());
									}
								}
								f.flush();
								fd.sync();
							} catch (Exception e) {
								stderr.println("[!]regexLogger log regex result error: " + e.getMessage());
							}
						}
					}
				}
			}
		}
	}

	private String getTime() {
		SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMdd-HHmmss");
		Date date = new Date(System.currentTimeMillis());
		return formatter.format(date);
	}

	private String getLogDir() {
		if (osInfo.toLowerCase().startsWith("win")) {
			return usrHome + separator + "Desktop" + separator + "log" + getTime();
		} else {
			return usrHome + separator + "regexLogger" + getTime();
		}
	}

	private void CloseCleanLogFileOutputStreams() {
		Set<FileOutputStream> tmpFiles = logFilesPattern.keySet();
		Iterator<FileOutputStream> Files = tmpFiles.iterator();
		while (Files.hasNext()) {
			FileOutputStream f = Files.next();
			try {
				f.close();
			} catch (Exception e) {
				stderr.println("[!]regexLogger closing log file error: " + e.getMessage());
			}
		}
		logFilesPattern.clear();
	}
	
	@Override
	public void extensionUnloaded() {
		// TODO Auto-generated method stub
		stdout.println("[+]RegexLogger was unloaded");
	}
}