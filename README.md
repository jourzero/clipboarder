# clipboarder

Burp app that adds "Copy as ..." in Burp context menus. All it does is copy a plain text version in the given UI context.

Current features

*Context: Proxy/HTTP-History*
* Add menu "Copy as raw HTTP" that puts HTTP request and response text into the clipboard
* Supports the selection of multiple HTTP messages

*Context: Target/Issues*
* Add Menu "Copy as plain text" that puts the issue details in free text form into the clipboard
* Add Menu "Copy as CSV" that puts the issue details in CSV format into the clipboard
* Supports the selection of multiple issues
* When an issue has multiple instances, all URLs are listed together and only the first Request/Response pair is included (in Base64).

Status: In Development
