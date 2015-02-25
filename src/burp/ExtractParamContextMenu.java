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

import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.JMenuItem;

public class ExtractParamContextMenu implements IContextMenuFactory {

	private ArrayList<JMenuItem> itemList;
	private IBurpExtenderCallbacks callbacks;
	
	public ExtractParamContextMenu(IBurpExtenderCallbacks mcallbacks) {
		callbacks = mcallbacks;
		itemList = new ArrayList<JMenuItem>();
	}
	
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation arg0) {
		itemList.clear();
		int tool = arg0.getToolFlag();
		if (tool == IBurpExtenderCallbacks.TOOL_INTRUDER ||
				tool == IBurpExtenderCallbacks.TOOL_PROXY ||
				tool == IBurpExtenderCallbacks.TOOL_REPEATER ||
				tool == IBurpExtenderCallbacks.TOOL_TARGET ||
				tool == IBurpExtenderCallbacks.TOOL_COMPARER) {

			itemList.add(new JMenuItem(new SearchParamAction(callbacks, arg0)));
			return itemList;
		} else {
			System.out.println(" ==> Unmanaged tool " + String.valueOf(tool));
		}
		
		return null;

	}
	
	class SearchParamAction extends AbstractAction {

		private static final long serialVersionUID = -6030591110872316798L;
		private int[] selection;
		private byte[] data;
		private boolean request;
		private ExtractParamDialog paramDialog;
		private IContextMenuInvocation contextMenu;
		private IBurpExtenderCallbacks callbacks;
		
		public SearchParamAction(IBurpExtenderCallbacks mcallbacks, IContextMenuInvocation mContextMenu) {
			super("Extract param values");
			callbacks = mcallbacks;
	        putValue(SHORT_DESCRIPTION, "Extract all the values of the given parameter from the proxy logs");
	        contextMenu = mContextMenu;
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			String sdata = new String();
			byte contextInv = contextMenu.getInvocationContext();
	        request = contextInv == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
	        		contextInv == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST ||
	        		contextInv == IContextMenuInvocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS;
	        
	        IHttpRequestResponse[] messages = contextMenu.getSelectedMessages();
	        
	        if (messages != null && messages.length > 0) {
	        	if (request) {
	        		data = messages[0].getRequest();
	        	}
	        	else {
	        		data = messages[0].getResponse();
	        	}
	        	
	        	if (data != null) {
		        	selection = contextMenu.getSelectionBounds();
		        	if (selection[0] != selection[1]) {
		        		sdata = callbacks.getHelpers().bytesToString(Arrays.copyOfRange(data,selection[0], selection[1]));
		        	}
	        	} else {
	        		System.out.println("Data is null");
	        	}
	        }
			paramDialog = new ExtractParamDialog(callbacks, sdata);
			paramDialog.pack();
			paramDialog.setLocationRelativeTo(null);
			paramDialog.setVisible(true);
		}
	}
}
