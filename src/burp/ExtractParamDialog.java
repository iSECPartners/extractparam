/**
 * Released as open source by iSec Partners / NCC Group
 * https://www.isecpartners.com/ - http://www.nccgroup.com/
 *
 * Developed by Gabriel Caudrelier, gabriel dot caudrelier at isecpartners dot com
 *
 * https://github.com/iSECPartners/extractparam
 *
 * Released under GPL see LICENSE for more information
 * */

package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;


public class ExtractParamDialog extends JFrame implements ActionListener  {
	private static final long serialVersionUID = -6990802100391410426L;
	private final JPanel contentPanel = new JPanel();
	private final JPanel optionsPanel = new JPanel();

	private JTextField nameTextField;
	private JCheckBox chckbxSearchInRequest;
	private JCheckBox chckbxSearchInResponse;
	private JCheckBox chckbxSearchInHTTPParam;
	private JCheckBox chckbxSearchInHTTPHeaders;
	private JCheckBox chckbxHtmlTextFields;
	private JCheckBox chckbxHtmlxmlAttributes;
	private JButton searchButton;
	private JButton cancelButton;
	private JProgressBar progressBar;
	private JCheckBox chckbxUrlDecodeRequests;
	private JCheckBox chckbxjsonFormat;
	private final JPanel scopePanel = new JPanel();;
	private JRadioButton everythingRadioButton;
	private JRadioButton inScopeOnlyRadioButton;
	private JButton closeButton;
	private final ButtonGroup buttonGroup = new ButtonGroup();
	private JScrollPane scrollpane;
	
	private String paramName;
	private boolean searchAllUrls = true;
	private IBurpExtenderCallbacks mCallbacks;
	private ExcludedModel excludedModel;
	
	private ResultModel dataModel;
	private JTable resTable;
	private JLabel globalResLabel;
	private JPopupMenu tablePopup;
	private final PopupListener menuListener = new PopupListener();
	
	private JTable excludedTable;
	private JPopupMenu ExcludedPopup;
	private final ExcludedListener excludedListener = new ExcludedListener();
	
	private static final String EXPORT_TO_FILE = "Export values to file";
	private static final String COPY_TO_CLIPBOARD = "Copy values";
	private static final String COPY_URLS_TO_CLIPBOARD = "Copy Urls for values";
	private static final String COPY_PROXU_IDS_TO_CLIPBOARD = "Copy Proxy IDs for values";
	private final static String START_TXT = "Search";
	private final static String STOP_TXT = "Cancel";
	private final static String DELETE_TXT = "Delete";
	private final static String INSERT_TXT = "Insert";
	private final static String EDIT_HERE_TXT = "Edit Here";
	private final static String DIALOG_TITLE_TXT = "Extract parameter values";
	private final static int COUNT_COLUMN_SIZE = 70;
	
	private final JFileChooser fileDialog = new JFileChooser();
	
	private ExtractTask worker;
	
	public ExtractParamDialog(IBurpExtenderCallbacks mcallbacks, String initialValue) {
		
		mCallbacks = mcallbacks;
		setTitle(DIALOG_TITLE_TXT);
		
		dataModel = new ResultModel();
		
		getContentPane().setLayout(new BorderLayout());
		
		getContentPane().add(optionsPanel, BorderLayout.PAGE_START);
		optionsPanel.setLayout(new GridLayout(2, 1, 0, 0));
		contentPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		getContentPane().add(contentPanel, BorderLayout.CENTER);
		contentPanel.setLayout(new BoxLayout(contentPanel,BoxLayout.Y_AXIS));
		{
			JPanel paramPanel = new JPanel();
			paramPanel.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)), "propertie/variable name", TitledBorder.CENTER, TitledBorder.TOP, null, null));
			paramPanel.setLayout(new FlowLayout(FlowLayout.RIGHT));
			optionsPanel.add(paramPanel);
			{
				nameTextField = new JTextField(initialValue);
				paramPanel.add(nameTextField);
				nameTextField.setColumns(30);
			}
			{
				chckbxUrlDecodeRequests = new JCheckBox("Url Decode requests values");
				chckbxUrlDecodeRequests.setSelected(true);
				paramPanel.add(chckbxUrlDecodeRequests);
			}
		}
		{
			JPanel targetPanel = new JPanel();
			targetPanel.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)), "Extract parameter from", TitledBorder.CENTER, TitledBorder.TOP, null, null));
			optionsPanel.add(targetPanel);
			targetPanel.setLayout(new GridLayout(5, 1, 0, 0));
			
			{
				chckbxSearchInHTTPHeaders = new JCheckBox("HTTP headers");
				chckbxSearchInHTTPHeaders.setSelected(true);
				chckbxSearchInHTTPHeaders.setToolTipText("Plain old search in the HTTP Headers");
				targetPanel.add(chckbxSearchInHTTPHeaders);
			}
			{
				chckbxSearchInHTTPParam = new JCheckBox("GET/POST parameters");
				chckbxSearchInHTTPParam.setSelected(true);
				chckbxSearchInHTTPParam.setToolTipText("The parameters are the one returned by the Burp API");
				targetPanel.add(chckbxSearchInHTTPParam);
			}
			
			
			{
				chckbxHtmlTextFields = new JCheckBox("HTML Text fields (name=\"param\" value=\"value\")");
				chckbxHtmlTextFields.setToolTipText("Regex search");
				chckbxHtmlTextFields.setSelected(true);
				targetPanel.add(chckbxHtmlTextFields);
			}
			{
				chckbxHtmlxmlAttributes = new JCheckBox("Script parameter format (Regex: param=\"value\")");
				chckbxHtmlxmlAttributes.setSelected(true);
				chckbxHtmlxmlAttributes.setToolTipText("Regex search");
				targetPanel.add(chckbxHtmlxmlAttributes);
			}
			{
				chckbxjsonFormat = new JCheckBox("JSON Format (\"param\":\"value\")");
				chckbxjsonFormat.setSelected(false);
				chckbxjsonFormat.setVisible(false);
				targetPanel.add(chckbxjsonFormat);
			}
			

			
		}
		
		{
			scopePanel.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)), "search scope", TitledBorder.CENTER, TitledBorder.TOP, null, null));
			optionsPanel.add(scopePanel);
			scopePanel.setLayout(new GridLayout(2, 2, 0, 0));
			{
				everythingRadioButton = new JRadioButton("All Urls");
				buttonGroup.add(everythingRadioButton);
				scopePanel.add(everythingRadioButton);
			}

			{
				chckbxSearchInRequest = new JCheckBox("In requests");
				chckbxSearchInRequest.setSelected(true);
				scopePanel.add(chckbxSearchInRequest);
			}
			{
				inScopeOnlyRadioButton = new JRadioButton("Urls in scope only");
				buttonGroup.add(inScopeOnlyRadioButton);
				inScopeOnlyRadioButton.setSelected(true);
				scopePanel.add(inScopeOnlyRadioButton);
			}
			{
				chckbxSearchInResponse = new JCheckBox("In Response");
				chckbxSearchInResponse.setSelected(true);
				scopePanel.add(chckbxSearchInResponse);
			}
		}
		
		{
			JPanel buttonPane = new JPanel();
			buttonPane.setLayout(new FlowLayout(FlowLayout.RIGHT));
			getContentPane().add(buttonPane, BorderLayout.SOUTH);
			
			{
				progressBar = new JProgressBar();
				progressBar.setIndeterminate(true);
				progressBar.setVisible(false);
				buttonPane.add(progressBar);
			}
			{
				searchButton = new JButton(START_TXT);
				searchButton.addActionListener(this);
				searchButton.setActionCommand(START_TXT);
				buttonPane.add(searchButton);
				getRootPane().setDefaultButton(searchButton);
			}
			{
				cancelButton = new JButton(STOP_TXT);
				cancelButton.addActionListener(this);
				cancelButton.setActionCommand(STOP_TXT);
				cancelButton.setEnabled(false);
				buttonPane.add(cancelButton);
			}
			
			{
				closeButton = new JButton("Close");
				closeButton.addMouseListener(new MouseAdapter() {
					@Override
					public void mouseClicked(MouseEvent e) {
						setVisible(false);
						dispose();
					}
				});
				buttonPane.add(closeButton);
			}
			
			{
				globalResLabel = new JLabel();
				contentPanel.add(globalResLabel);
				resTable = new JTable(dataModel);

				resTable.getColumnModel().getColumn(1).setMaxWidth(COUNT_COLUMN_SIZE);
				resTable.setAutoCreateRowSorter(true);

				scrollpane = new JScrollPane(resTable);
				contentPanel.add(scrollpane);
				
				tablePopup = new JPopupMenu();
				JMenuItem menuItem = new JMenuItem(EXPORT_TO_FILE);
			    menuItem.addActionListener(menuListener);
			    tablePopup.add(menuItem);
			    menuItem = new JMenuItem(COPY_TO_CLIPBOARD);
			    menuItem.addActionListener(menuListener);
			    tablePopup.add(menuItem);
			    menuItem = new JMenuItem(COPY_URLS_TO_CLIPBOARD);
			    menuItem.addActionListener(menuListener);
			    tablePopup.add(menuItem);
			    menuItem = new JMenuItem(COPY_PROXU_IDS_TO_CLIPBOARD);
			    menuItem.addActionListener(menuListener);
			    tablePopup.add(menuItem);
			    
			    resTable.setComponentPopupMenu(tablePopup);
			}
			
			{
				JPanel excludedPane = new JPanel();
				excludedPane.setBorder(new TitledBorder(new LineBorder(new Color(184, 207, 229)), "Exclusions", TitledBorder.CENTER, TitledBorder.TOP, null, null));
				excludedModel = new ExcludedModel();
				excludedTable = new JTable(excludedModel);
				excludedTable.setPreferredScrollableViewportSize(new Dimension(400,80));
				excludedTable.getColumnModel().getColumn(1).setMaxWidth(COUNT_COLUMN_SIZE);
				scrollpane = new JScrollPane(excludedTable);
				excludedPane.add(scrollpane);
				optionsPanel.add(excludedPane);
				
				ExcludedPopup = new JPopupMenu();
				JMenuItem menuItem = new JMenuItem(DELETE_TXT);
			    menuItem.addActionListener(excludedListener);
			    ExcludedPopup.add(menuItem);
			    menuItem = new JMenuItem(INSERT_TXT);
			    menuItem.addActionListener(excludedListener);
			    ExcludedPopup.add(menuItem);
			    excludedTable.setComponentPopupMenu(ExcludedPopup);
			}
		}
		initialize();
	}
	
	
	class ExcludedListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			int[] rows = excludedTable.getSelectedRows();
			
			if (rows.length > 0) {
				if (e.getActionCommand() == DELETE_TXT) {
		            for (int i = 0; i < rows.length; i++) {
		            	excludedModel.removePattern(rows[i]);
		            }
				}
			} else if (e.getActionCommand() == INSERT_TXT) {
				int index = excludedModel.addPattern(EDIT_HERE_TXT);
				excludedTable.editCellAt(index,0);
			}
		}
	}
	class PopupListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {
			
			int[] rows = resTable.getSelectedRows();
			if (rows.length > 0) {
				if (e.getActionCommand() == EXPORT_TO_FILE) {
					int returnVal = fileDialog.showOpenDialog(ExtractParamDialog.this);
					if (returnVal == JFileChooser.APPROVE_OPTION) {
			            File file = fileDialog.getSelectedFile();
			            FileWriter writer;
						try {
							writer = new FileWriter(file);
				            PrintWriter textWriter = new PrintWriter( writer );
				            for (int i = 0; i < rows.length; i++) {
				            	textWriter.println(dataModel.getValue(rows[i]));
				            }
				            textWriter.close();
						} catch (IOException e1) {
							e1.printStackTrace();
						} 
				    }
				} else if (e.getActionCommand() == COPY_TO_CLIPBOARD) {
					StringBuilder res = new StringBuilder();
					for (int i = 0; i < rows.length; i++) {
						res.append(dataModel.getValue(rows[i]));
						res.append("\n");
					}

					StringSelection stringSelection = new StringSelection (res.substring(0,res.length() - 1));
					Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
					clip.setContents (stringSelection, null);
				} else if (e.getActionCommand() == COPY_URLS_TO_CLIPBOARD) {
					StringBuilder res = new StringBuilder();
					for (int i = 0; i < rows.length; i++) {
						String[] urls = dataModel.getUrls(rows[i]);
						System.out.println("Urls size " + String.valueOf(urls.length));
						for (int j = 0; j < urls.length; j++) {
							res.append(urls[j]);
							res.append("\n");
						}
					}

					StringSelection stringSelection = new StringSelection (res.substring(0,res.length() - 1));
					Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
					clip.setContents (stringSelection, null);
				} else if (e.getActionCommand() == COPY_PROXU_IDS_TO_CLIPBOARD) {
					StringBuilder res = new StringBuilder();
					for (int i = 0; i < rows.length; i++) {
						Integer[] ids = dataModel.getProxyIds(rows[i]);
						System.out.println("ProxyIds size " + String.valueOf(ids.length));
						for (int j = 0; j < ids.length; j++) {
							res.append(ids[j]);
							res.append("\n");
						}
					}

					StringSelection stringSelection = new StringSelection (res.substring(0,res.length() - 1));
					Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();
					clip.setContents (stringSelection, null);
				}
			}
	    }
	}
	
	public void actionPerformed(ActionEvent e) {

        if (START_TXT == e.getActionCommand()) {
    		dataModel.clear();
    		searchAllUrls = everythingRadioButton.isSelected();
    		dataModel.setSearchScope(searchAllUrls);
        	searchButton.setEnabled(false);
            cancelButton.setEnabled(true);
            progressBar.setVisible(true);
            (worker = new ExtractTask()).execute();
        } else if (STOP_TXT == e.getActionCommand()) {
        	searchButton.setEnabled(true);
            cancelButton.setEnabled(false);
            worker.cancel(true);
            worker = null;
            progressBar.setVisible(false);
        }
 
    }
	
	private void initialize() {
		excludedModel.addPattern("^image/.*$");
		excludedModel.addPattern("^application/x-shockwave-flash$");
	}
	

	
	public void setParameter(String data) {
		nameTextField.setText(data);
	}
		
	private static class ResValue {
        private final String extractValue;
        private final String url;
        private int proxyId;
        ResValue(String extractValue, java.net.URL url, int proxyId) {
            this.extractValue = extractValue.trim();
            this.url = url.toString();
            this.proxyId = proxyId;
        }
    }
 
    private class ExtractTask extends SwingWorker<Void, ResValue> {
    	private boolean searchHTTPParam;
    	private boolean searchXmlAttributes;
    	private boolean searchHtmlInputFields;
    	private boolean searchJSON;
    	private boolean decode;
    	private boolean searchHTTPHeaders;
    	private boolean searchResponse;
    	private boolean searchRequest;
    	private Pattern xmlAttrPattern;
    	private Pattern inputFieldPattern;
    	private final Pattern contentTypePattern = Pattern.compile("^Content-Type: (.*)$");
    	private Pattern[] excludedPatterns;
    	
    	private boolean isExcluded(String[] headers) {
    		if (headers != null && excludedPatterns.length > 0) {
    			for (int j = 0; j < headers.length; j++) {
    				Matcher matcher = contentTypePattern.matcher(headers[j]);
    				if (matcher.find()) {
    					String typeValue = matcher.group(1);
    					if (typeValue != null) {
							for (int i = 0; i < excludedPatterns.length; i++) {
								Matcher matcher2 = excludedPatterns[i].matcher(typeValue);
								if (matcher2.find()) {
									return true;
								}
							}
    					} else {
    						return true;
    					}
    				}
    			}
    		}
    		return false;
    	}
    	
        @Override
        protected Void doInBackground() {
        	globalResLabel.setText("");
    		paramName = nameTextField.getText();
    		
    		xmlAttrPattern = Pattern.compile("\\W" + paramName + "\\s?=\\s+([^\\s]*)\\s");
    		inputFieldPattern = Pattern.compile("name=\"" + paramName + "\" (type=\"hidden\")? value=\"?([^\"]*)\"? ");
    		
    		searchHTTPParam = chckbxSearchInHTTPParam.isSelected();
    		searchXmlAttributes = chckbxHtmlxmlAttributes.isSelected();
    		searchHtmlInputFields = chckbxHtmlTextFields.isSelected();
    		searchJSON = chckbxjsonFormat.isSelected();
    		decode = chckbxUrlDecodeRequests.isSelected();
    		searchHTTPHeaders = chckbxSearchInHTTPHeaders.isSelected();
    		searchResponse = chckbxSearchInResponse.isSelected();
    		searchRequest = chckbxSearchInRequest.isSelected();
    		excludedPatterns = excludedModel.getPatterns();
    		IHttpRequestResponse[] requestList = mCallbacks.getProxyHistory();

    		for (int i = 0; i < requestList.length; i++) {
    			try {
    				IRequestInfo info = mCallbacks.getHelpers().analyzeRequest(requestList[i]);
    				URL url = info.getUrl();

    				if (searchAllUrls || mCallbacks.isInScope(url)) {
    					// System.out.println("Processing response " + String.valueOf(i));
    					if (searchRequest)
    						processMessage(requestList[i].getRequest(), url,i);
    					if (searchResponse)
    						processMessage(requestList[i].getResponse(), url,i);
    				}	
    				
			
    			} catch (Exception e) {
    				e.printStackTrace();
    			}
    			if (isCancelled())
    				break;
    		}		
        	return null;
        }
        
        private void processMessage(byte[] message, URL url, int proxyId) {
        	if (message == null || message.length < 1) // nothing to do here
        		return;
        	
        	if (isExcluded(mCallbacks.getHeaders(message))) {
        		return;
        	}

			if (searchHTTPHeaders) {
				String[] httpHeaders = mCallbacks.getHeaders(message);
				for (int j = 0; j < httpHeaders.length; j++) {
					String lookedAt = httpHeaders[j];
					int sep = lookedAt.indexOf(':');
					if (sep != -1 && sep > 0) {
						if (lookedAt.substring(0, sep).equals(paramName)) {
							if (lookedAt.length() > sep) {
								String svalue = lookedAt.substring(sep+ 1);
								publish(new ResValue(svalue, url,proxyId));
							}
							
						}
					}
				}
			}
			
			if (searchHTTPParam) {
				// Extracting parameters from HTTP request or cookies
				String[][] paramList = mCallbacks.getParameters(message);

				for (int j = 0; j < paramList.length; j++) {
					if (paramList[j].length > 1) {        								
						if (paramList[j][0].equals(paramName)) {
						String svalue = paramList[j][1];
						if (decode)
							try {
								svalue = URLDecoder.decode(svalue, "UTF-8");
							} catch (UnsupportedEncodingException e) {
								System.out.println(e.getMessage());
							}
						publish(new ResValue(svalue, url,proxyId));
						}
					}
				}
			}
			
			if (searchXmlAttributes || searchHtmlInputFields || searchJSON) {
				String sResponse = new String(message);
				if (searchXmlAttributes) {
					Matcher matcher = xmlAttrPattern.matcher(sResponse);
					if (matcher.find()) {
						if (sResponse.charAt(matcher.end()) == '"' && sResponse.length() > matcher.end()) {
							int endIndex = sResponse.indexOf('"', matcher.end());
							if (endIndex > 0)
								publish(new ResValue(sResponse.substring(matcher.end() + 1, endIndex), url,proxyId));
						} else if (sResponse.charAt(matcher.end()) == '\'' && sResponse.length() > matcher.end()) {
							int endIndex = sResponse.indexOf('\'', matcher.end());
							if (endIndex != -1)
								publish(new ResValue(sResponse.substring(matcher.end() + 1, sResponse.indexOf('\'', matcher.end())), url,proxyId));
						} else if (sResponse.charAt(matcher.end()) != '=' && sResponse.length() > matcher.end()) {
				
							TreeMap<Integer,String> values = new TreeMap<Integer,String>();
							char[] delimiters = { ';' , ' ' };
							
							for (int l = 0; l < delimiters.length; l++) {
								int endIndex = sResponse.indexOf(delimiters[l], matcher.end());
								if (endIndex != -1) {
									String test1 = sResponse.substring(matcher.end(), endIndex);
									values.put(test1.length(),test1);
								}
							}
							publish(new ResValue(values.firstEntry().getValue(), url,proxyId));
						}
					}
				}
			
				if (searchHtmlInputFields) {
					Matcher matcher = inputFieldPattern.matcher(sResponse);
					while (matcher.find()) {
						publish(new ResValue(matcher.group(2), url,proxyId));
					}
				}
				
				if (searchJSON) {
					Pattern inputFieldPattern = Pattern.compile("\"" + paramName + "\":\"([^\"]*)\"");
					Pattern inputFieldPattern2 = Pattern.compile("\"" + paramName + "\":\\s*([true|false|null])");
					Pattern inputFieldPattern3 = Pattern.compile("\"" + paramName + "\":\\s*(-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)");
					Matcher matcher = inputFieldPattern.matcher(sResponse);
					
					while (matcher.find()) {
						//System.out.println("JSON pattern 1");
						publish(new ResValue(matcher.group(1), url,proxyId));
					}
					
					matcher = inputFieldPattern2.matcher(sResponse);
					while (matcher.find()) {
						//System.out.println("JSON pattern 2");
						publish(new ResValue(matcher.group(1), url,proxyId));
					}
					
					matcher = inputFieldPattern3.matcher(sResponse);
					while (matcher.find()) {
						//System.out.println("JSON pattern 3");
						publish(new ResValue(matcher.group(1), url,proxyId));
					}
				}
			}
        }
 
        @Override
        protected void process(List<ResValue> list) {
        	int size = list.size();
        	
        	for (int i = 0; i < size ; i++) {
        		dataModel.addResult(list.get(i));
        	}
        }
        
        public void done() {
        	globalResLabel.setText(dataModel.getGlobalResults());
    		resTable.getColumnModel().getColumn(1).setMaxWidth(COUNT_COLUMN_SIZE);
    		
    		searchButton.setEnabled(true);
            cancelButton.setEnabled(false);
            worker = null;
            progressBar.setVisible(false);
        }
        
    }
    
	class ExcludedModel extends AbstractTableModel {

		private ArrayList<String> exceptionsPattern;
		private ArrayList<Boolean> checkedPattern;
		private static final int PATTERN_COL = 0;
		private static final int CHECK_COL = 1;
		private static final long serialVersionUID = -236855951358800805L;

		public ExcludedModel() {
			exceptionsPattern = new ArrayList<String>();
			checkedPattern = new ArrayList<Boolean>();
		}
		
		public int addPattern (String regexp) {
			exceptionsPattern.add(regexp);
			checkedPattern.add(Boolean.TRUE);
			int index = exceptionsPattern.size() - 1;
			fireTableRowsInserted(index, index);
			return index;
		}
		
		public void removePattern(int index) {
			if (index > -1 && index < exceptionsPattern.size()) {
				exceptionsPattern.remove(index);
				checkedPattern.remove(index);
				fireTableRowsDeleted(index, index);
			}
		}
		
		public Pattern[] getPatterns() {
			
			ArrayList<Pattern> list = new ArrayList<Pattern>();
			
			for (int i = 0; i < exceptionsPattern.size(); i++) {
				if (checkedPattern.get(i))
					list.add(Pattern.compile(exceptionsPattern.get(i)));
			}
			return (Pattern[]) list.toArray(new Pattern[list.size()]);
		}
		
		@Override
        public Class<?> getColumnClass(int col) {
			if (col == PATTERN_COL)
				return String.class;
			else if (col == CHECK_COL)
				return Boolean.class;
			
			return null;
        }
		
		@Override
		public boolean isCellEditable(int row, int col)
        { return true; }
		
		@Override
		public void setValueAt(Object value, int row, int col) {
			if (col == PATTERN_COL) {
				exceptionsPattern.set(row, (String) value);
			} else if (col == CHECK_COL) {
				checkedPattern.set(row, (Boolean) value);
			}
			fireTableCellUpdated(row, col);
	    }
		
		public void clear() {
			exceptionsPattern.clear();
			checkedPattern.clear();
			fireTableStructureChanged();
		}
		
		@Override
		public String getColumnName(int col) {
			if (col == PATTERN_COL)
				return "Content-Type";
			else if (col == CHECK_COL) {
				return "Enabled";
			} else
				return "";
	    }
		
		@Override
		public int getRowCount() {
			return exceptionsPattern.size();
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public Object getValueAt(int row, int col) {
			if (row > -1 && row < exceptionsPattern.size()) {
				if (col == PATTERN_COL) {
					return exceptionsPattern.get(row);
				} else if (col == CHECK_COL) {
					return checkedPattern.get(row);
				}
			}
			return null;
		}
		
	}
	
	class ResultModel extends AbstractTableModel {
		private static final long serialVersionUID = -6203452783334639393L;
		private ArrayList<String> data;
		private ArrayList<Integer> count;
		private ArrayList<HashSet<String>> urls;
		private ArrayList<HashSet<Integer>> proxyIds;
		private int total;
		private boolean searchScope;
		
		public void setSearchScope(boolean searchScope) {
			this.searchScope = searchScope;
		}

		public ResultModel() {
			data = new ArrayList<String>();
			count = new ArrayList<Integer>();
			urls = new ArrayList<HashSet<String>>();
			proxyIds = new ArrayList<HashSet<Integer>>();
			total = 0;
		}

		public void addResult(ResValue res) {
			if (res.extractValue != null) {
				if (!res.extractValue.isEmpty()) {
					int index = data.indexOf(res.extractValue);
					
					if (index != -1) {
						count.set(index, count.get(index) + 1);
						if (res.url != null) {
							urls.get(index).add(res.url);
						}
						
						if (res.proxyId > 0) {
							proxyIds.get(index).add(res.proxyId);
						}
						
						fireTableCellUpdated(index, 1);
					} else {
						data.add(res.extractValue);
						count.add(1);
						
						HashSet<String> list = new HashSet<String>();
						if (res.url != null) {
							list.add(res.url);
						} else {
							list.add("null");
						}
						urls.add(list);
						
						HashSet<Integer> idlist = new HashSet<Integer>();
						idlist.add(res.proxyId);
						proxyIds.add(idlist);
						fireTableRowsInserted(index, index);
					}
					total++;
				}
			}
		}
		
		public String getValue(int row) {
			if (row < data.size())
				return data.get(row);
			else
				return null; 
		}
		
		public String[] getUrls(int row) {
			if (row < urls.size()) {
				String[] blist = new String[urls.get(row).size()];
				blist = urls.get(row).toArray(blist);
				return blist;
			}
			else
				return null;
		}
		
		public Integer[] getProxyIds(int row) {
			if (row < proxyIds.size()) {
				Integer[] blist = new Integer[proxyIds.get(row).size()];
				blist = proxyIds.get(row).toArray(blist);
				return blist;
			}
			else
				return null;
		}
		
		@Override
        public Class<?> getColumnClass(int columnIndex) {
			if (columnIndex == 0)
				return String.class;
			else
				return Integer.class;
        }
		
		@Override
		public String getColumnName(int col) {
			if (col == 0)
				return "Value";
			else
				return "count";
	    }
		
		@Override
		public boolean isCellEditable(int row, int col) {
			return false; 
		}
		
		public void clear() {
			total = 0;
			data.clear();
			count.clear();
			urls.clear();
			fireTableStructureChanged();
		}
		
		public int getTotal() {
			return total;
		}
		
		@Override
		public int getRowCount() {
			return data.size();
		}

		@Override
		public int getColumnCount() {
			return 2;
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			if (columnIndex == 0) {
				return data.get(rowIndex);
			} else {
				return count.get(rowIndex);
			}
		}
		
		public String getGlobalResults() {
		
			return String.format("Found %d occurrence(s) of \"%s\" - %d unique values (%s)", total, paramName,data.size(),(searchScope ? "Everything" : "scope only"));
		}
	}
}
