# Clipboarder

Burp app that adds "Copy as ..." in Burp context menus. All it does is copy a plain text version in the given UI context.

Current features

_Context: Proxy/HTTP-History_
* Add menu "Copy as raw HTTP to clipboard" that puts HTTP request and response text into the clipboard
* Supports the selection of multiple HTTP messages

_Context: Target/Issues_
* Add Menu "Copy as plain text to clipboard" that puts the issue details in free text form into the clipboard
* Supports the selection of multiple issues
* When an issue has multiple instances, all URLs are listed together
* only the first Request/Response pair is included as Evidence data (Base64-encoded).

Status: In Development
