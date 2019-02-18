# Clipboarder

Burp app that adds "Copy as ... to clipboard" in Burp context menus. All it does is copy plain text to the clipboard, in the given UI context.

## Current features

### Context: Proxy/HTTP-History
* Add menu "Copy as raw HTTP to clipboard" that puts HTTP request and response text into the clipboard
* Supports the selection of multiple HTTP messages

### Context: Target/Issues
* Add Menu "Copy as free text to clipboard" that puts the issue details in free text form into the clipboard
 * Note that the clipboard content can be pasted into [WAPTRun](https://github.com/jourzero/waptrun)'s Notes field.
* Supports the selection of multiple issues
* When an issue has multiple instances, all URLs are listed together
* Only the HTTP Request/Response pair(s) for the first instance of an issue is included as Evidence data (Base64-encoded)

Status: Released
