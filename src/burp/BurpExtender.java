/*
 * Clipboarder extension
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
import java.util.Base64;

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
        this.stdout.println(
                  "\n=======================================================================================================\n"
                + "\nUse " + EXT_NAME+" to quickly extract data from Burp to feed other tools or reports:"
                + "\n- In Proxy/History, choose " + PROXYHIST_CONTEXTMENU_COPYRAW 
                + "\n- In Target/Issues, choose " + TARGETISSUES_CONTEXTMENU_COPYTEXT
                + "\nLatest source here: https://github.com/jourzero/clipboarder"
                + "\nCheers,"
                + "\nEric Paquet <eric@jourzero.com>"
                + "\n"
                + "\nNotes:"
                + "\n- Evidence corresponds to the Request/Response for the 1st instance of an issue, encoded in Base64"
                + "\n- Remediation Details (when included) is specific to the 1st instance of an issue (others are not kept)"
                + "\n- Issue Details (when included) is specific to the 1st instance of an issue (others are not kept)"
                + "\n=======================================================================================================\n");
    }

    /**
     * Create Burp menu items
     * @param invocation
     * @return List of menu items to create in Burp context
     */
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        try{
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
        catch (Exception e) {
            this.stderr.println("ERROR: Failed creating menus for Clipboarder!");
            e.printStackTrace(this.stderr);
        }      
        return null;
    }
    
    /**
     * Copy select Burp scan issues as plain text to the clipboard
     * @param issues List of selected issues in the Target tab
     */
    private void copyIssueText(IScanIssue[] issues) {
        StringBuilder buf = new StringBuilder();
        String issueName="", prevIssueName="", url="", prevUrl="";
        IHttpRequestResponse firstMsg = null;
        strBuf = null;
        
        // Iterate through all selected issues
        for (IScanIssue issue : issues) {
            issueName = issue.getIssueName();
            //this.stdout.println("DEBUG: Reading data for issue: " + issueName);
            
            // If the issue name at hand is different, print the details.
            // If it is not different (from the previous), just print the URL. 
            // This logic essentially collapses multiple instances of the same issue.
            if (!issueName.equals(prevIssueName)){
                this.stdout.println("Copying issue data for: " + issue.getIssueName());
                firstMsg = null;
                strBuf = null;
                buf.append("\n\n\n");
                buf.append("\nIssue: "                      + issue.getIssueName());
                buf.append("\nSeverity: "                   + issue.getSeverity());
                buf.append("\nConfidence: "                 + issue.getConfidence());
                if (issue.getIssueBackground() != null)       buf.append("\nIssue Background:\n"                       + issue.getIssueBackground());
                if (issue.getRemediationBackground() != null) buf.append("\n~\nRemediation Background:\n"              + issue.getRemediationBackground());
                if (issue.getIssueDetail() != null)           buf.append("\n~\nIssue Details:\n"        + issue.getIssueDetail());
                if (issue.getRemediationDetail() != null)     buf.append("\n~\nRemediation Details:\n"  + issue.getRemediationDetail());
                
                // Add evidence data if applicable
                if (issue.getHttpMessages().length > 0){
                    buf.append("\n~\nEvidence: ");
                    strBuf = new StringBuilder();
                    for (IHttpRequestResponse msg: issue.getHttpMessages()){
                        this.buildRawHttpBuffer(msg);
                    }
                    if (strBuf != null){
                        buf.append(toBase64(strBuf.toString()));
                    }
                }
                buf.append("\n~\nURL(s):");
            }
            
            // Add URLs that are affected by the issue
            url = issue.getUrl().toString();
            if (!url.equals(prevUrl)){
                buf.append("\n - " + url);
            }
            prevUrl = url;
            prevIssueName = issueName;
        }

        // Send to clipboard
        try{
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(buf.toString().trim()), this);  
        }
        catch (Exception e) {
            this.stderr.println("ERROR: Failed copying issue data to clipboard!");
            e.printStackTrace(this.stderr);
        }        
    }

    /**
     * Copy the raw HTTP text from selected messages in the Burp Proxy History
     * @param messages selected messages in Burp's proxy history
     */
    private void copyRawHttp(IHttpRequestResponse[] messages) {
        strBuf = new StringBuilder();
        for (IHttpRequestResponse message : messages) {
            buildRawHttpBuffer(message);
        }

        // Send to clipboard
        try{
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(strBuf.toString().trim()), this);
            this.stdout.println("Copied raw HTTP data to clipboard for " + messages.length + " messages");
        }
        catch (Exception e) {
            this.stderr.println("ERROR: Failed copying raw HTTP data to clipboard!");
            e.printStackTrace(this.stderr);
        }
    }

    /**
     * Build the Raw HTTP text representation for a Burp message
     * @param message Burp HTTP RequestResponse object
     */
    private void buildRawHttpBuffer(IHttpRequestResponse message){
        
        IRequestInfo ri = this.helpers.analyzeRequest(message);
        byte[] req = message.getRequest();
        Boolean firstHeader = true;
        for (String header : ri.getHeaders()) {
            if (firstHeader){
                String[] elements = header.split(" ");
                String url = elements[1];
                strBuf.append("\n======== PATH: " + url + " ========");
                strBuf.append("\n===REQUEST===\n");
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
        strBuf.append("\n===\n");

        byte[] rsp = message.getResponse();
        strBuf.append("\n===RESPONSE===\n");
        if (rsp.length > 0) {
            strBuf.append(this.helpers.bytesToString(rsp));
        }
        strBuf.append("\n===");
    }

    /**
     * Covert plain text into Base64
     * @param text Text to encode in Base64
     * @return Base64-encoded output
     */
    private String toBase64(String text){        
        return Base64.getEncoder().encodeToString(text.getBytes());
    }

    @Override
    public void lostOwnership(Clipboard aClipboard, Transferable aContents) {
    }

}
