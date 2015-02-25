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

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender {

	private static IBurpExtenderCallbacks burp;
	private static PrintWriter errOut;
	private static PrintWriter stdOut;
	private static final String VERSION = "1.1";
	
	public BurpExtender() {

	}
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		errOut = new PrintWriter(callbacks.getStderr());
		stdOut = new PrintWriter(callbacks.getStdout());

		callbacks.registerContextMenuFactory(new ExtractParamContextMenu(callbacks));
		callbacks.setExtensionName("Extract parameter v" + VERSION );
		burp = callbacks;
	}
	
	public static final void alert(String message) {
		burp.issueAlert(message);
		stdOut.println(message);
	}
	
	public static final void error(String message) {
		burp.issueAlert(message);
		errOut.println(message);
	}
	
	public static final void message (String message) {
		stdOut.println(message);
	}
}
