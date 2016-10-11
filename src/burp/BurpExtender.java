/*
 * Burpaholic extension
 */
package burp;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.List;
import javax.swing.JMenuItem;
import java.util.Base64.Encoder;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner {
    private IExtensionHelpers helpers;
    private static final String EXT_NAME                            = "Clipboarder";
    private static final String PROXYHIST_CONTEXTMENU_COPYRAW       = "Copy as raw HTTP to clipboard";
    private static final String TARGETISSUES_CONTEXTMENU_COPYTEXT   = "Copy as free text to clipboard";
    private static StringBuilder strBuf = new StringBuilder(); 
    private IScanIssue[] selectedIssues = null;
    PrintWriter stdout = null;
    PrintWriter stderr = null;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXT_NAME);
        callbacks.registerContextMenuFactory((IContextMenuFactory)this);
        this.stdout.println("Use " + EXT_NAME+" to quickly extract data from Burp to feed other tools or reports:"
                + "\n- In Proxy/History, choose " + PROXYHIST_CONTEXTMENU_COPYRAW 
                + "\n- In Target/Issues, choose " + TARGETISSUES_CONTEXTMENU_COPYTEXT
                + "\nCheers,\nEric Paquet <eric@jourzero.com>\n");
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
        int issueType=0, prevIssueType=0;
        Boolean firstInstance = true;
        IHttpRequestResponse firstMsg = null;
        strBuf = null;
        
        for (IScanIssue issue : issues) {
            issueType = issue.getIssueType();
            if (issueType != prevIssueType){
                firstInstance = true;
                firstMsg = null;
                strBuf = null;
                buf.append("----------------------------------------------------------------");
                buf.append("\nIssue: "                      + issue.getIssueName());
                buf.append("\nIssue Type: "                 + issueType);
                buf.append("\nSeverity: "                   + issue.getSeverity());
                buf.append("\nConfidence:  "                + issue.getConfidence());
                buf.append("\nIssue Background:\n"          + issue.getIssueBackground());
                buf.append("\n~\nIssue Details:\n"          + issue.getIssueDetail());
                buf.append("\n~\nRemediation Background:\n" + issue.getRemediationBackground());
                buf.append("\n~\nRemediation Details:\n"    + issue.getRemediationDetail());
                buf.append("\n~\nEvidence Data (Base64): ");     
                firstMsg = issue.getHttpMessages()[0];
                strBuf = new StringBuilder();
                this.buildRawHttpBuffer(firstMsg);
                // Add Evidence data
                if (strBuf != null){
                    buf.append(this.toBase64(strBuf.toString()));
                }
                buf.append("\n~\nAffected URL(s):");
            }
            else
                firstInstance = false;
            
            // Add URLs that are affected by the issue
            buf.append("\n - " + issue.getUrl().toString());
            prevIssueType = issueType;
            
        }

        // Send to clipboard
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(buf.toString()), this);  
    }

    private void copyRawHttp(IHttpRequestResponse[] messages) {
        strBuf = new StringBuilder();
        for (IHttpRequestResponse message : messages) {
            buildRawHttpBuffer(message);
        }

        // Send to clipboard
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(strBuf.toString()), this);
    }

    private void buildRawHttpBuffer(IHttpRequestResponse message){
        
        IRequestInfo ri = this.helpers.analyzeRequest(message);
        byte[] req = message.getRequest();
        Boolean firstHeader = true;
        for (String header : ri.getHeaders()) {
            if (firstHeader){
                String[] elements = header.split(" ");
                String url = elements[1];
                strBuf.append("\n======== PATH: " + url + " ========");
                strBuf.append("\n*** REQUEST ***\n");
                firstHeader = false;
            }
            strBuf.append(header);
            strBuf.append("\n");
        }
        int bo = ri.getBodyOffset();
        if (bo < req.length - 1) {
            strBuf.append("\n");
            strBuf.append(new String(req, bo, req.length - bo));
        }

        byte[] rsp = message.getResponse();
        strBuf.append("\n*** RESPONSE ***\n");
        if (rsp.length > 0) {
            strBuf.append(this.helpers.bytesToString(rsp));
        }
        strBuf.append("\n****************");
    }

    private String escapeQuotes(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
    
    private String toBase64(String text){        
        return java.util.Base64.getEncoder().encodeToString(text.getBytes());
    }

    @Override
    public void lostOwnership(Clipboard aClipboard, Transferable aContents) {
    }

}
