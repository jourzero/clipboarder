/*
 * Burpaholic extension
 */
package burp;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
//import java.net.URL;
import java.util.Collections;
import java.util.List;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner {
    private IExtensionHelpers helpers;
    private static final String EXT_NAME                            = "Clipboarder";
    private static final String PROXYHIST_CONTEXTMENU_COPYRAW       = "Copy as raw HTTP";
    private static final String TARGETISSUES_CONTEXTMENU_COPYTEXT   = "Copy as free text";
    private static final String TARGETISSUES_CONTEXTMENU_COPYTSV    = "Copy as tab-delimited";
    private IScanIssue[] selectedIssues = null;
    PrintWriter stdout = null;
    PrintWriter stderr = null;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXT_NAME);
        callbacks.registerContextMenuFactory((IContextMenuFactory)this);
        this.stdout.println("Use " + EXT_NAME+" to quickly extract data from Burp to feed other tools or during reporting.\n" + "Cheers,\nEric Paquet <eric@jourzero.com>\n");

    }

    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages != null && messages.length != 0) {
            JMenuItem i = new JMenuItem(PROXYHIST_CONTEXTMENU_COPYRAW);
            i.addActionListener(new ActionListener(){

                @Override
                public void actionPerformed(ActionEvent e) {
                    BurpExtender.this.copyRawHttp(messages);
                }
            });
            return Collections.singletonList(i);
        }
        final IScanIssue[] issues = invocation.getSelectedIssues();
        if (issues != null && issues.length != 0) {
            JMenuItem i = new JMenuItem(TARGETISSUES_CONTEXTMENU_COPYTEXT);
            i.addActionListener(new ActionListener(){

                @Override
                public void actionPerformed(ActionEvent e) {
                    BurpExtender.this.copyIssueText(issues);
                }
            });
            return Collections.singletonList(i);
        }
        else{
            return null;
        }
    }
    
    private void copyIssueText(IScanIssue[] issues) {
        StringBuilder buf = new StringBuilder();
        int issueId=0, prevIssueId=0;
        
        for (IScanIssue issue : issues) {
            issueId = issue.getIssueType();
            if (issueId != prevIssueId){
                buf.append("\n");
                buf.append("\nIssue: "                  + issue.getIssueName());
                buf.append("\nIssue Type: "             + issueId);
                buf.append("\nSeverity: "               + issue.getSeverity());
                buf.append("\nIssue Background: "       + issue.getIssueBackground());
                buf.append("\nIssue Details: "          + issue.getIssueDetail());
                buf.append("\nRemediation Background: " + issue.getRemediationBackground());
                buf.append("\nRemediation Details: "    + issue.getRemediationDetail());
                buf.append("\nConfidence: "             + issue.getConfidence());
                buf.append("\nAffected URL(s): ");
            }
            //buf.append("\nHost: "                   + issue.getHttpService().getHost());
            buf.append("\n - "                    + issue.getUrl().toString());
            prevIssueId = issueId;
        }

        // Send to clipboard
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(buf.toString()), this);  
    }

    private void copyRawHttp(IHttpRequestResponse[] messages) {
        StringBuilder buf = new StringBuilder();
        int counter = 0;
        for (IHttpRequestResponse message : messages) {
            counter++;
            IRequestInfo ri = this.helpers.analyzeRequest(message);
            byte[] req = message.getRequest();
            buf.append("\n=== REQUEST #" + counter + " ===\n");
            for (String header : ri.getHeaders()) {
                buf.append(header);
                buf.append("\n");
            }
            int bo = ri.getBodyOffset();
            if (bo < req.length - 1) {
                buf.append("\n");
                buf.append(new String(req, bo, req.length - bo));
            }

            byte[] rsp = message.getResponse();
            buf.append("\n=== RESPONSE #" + counter + " ===\n");
            if (rsp.length > 0) {
                buf.append(this.helpers.bytesToString(rsp));
            }
            buf.append("\n=== END OF #" + counter + " ===\n");
        }

        // Send to clipboard
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(buf.toString()), this);
    }


    private String escapeQuotes(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    @Override
    public void lostOwnership(Clipboard aClipboard, Transferable aContents) {
    }

}
