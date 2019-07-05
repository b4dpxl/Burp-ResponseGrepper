Burp extension to auto-extract values from HTTP Responses based on a Regular Expression. 
Extracts the match and any named or unnamed groups. A bit like Burp Intruder's "Grep - Extract" option, but should work on any Responses. 

The regex is defined per-request. It will extract the full match, and also highlight and extract any groups defined in the regex. Named groups can also be used for more detail in the regex.

![screenshot](https://github.com/b4dpxl/Burp-ResponseGrepper/blob/master/screenshots/results_pane.png?raw=true)

This is a Python extension, so it needs jython to be configured.
See [here](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite)
