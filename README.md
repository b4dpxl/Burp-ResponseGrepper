This Burp extension will auto-extract and display values from HTTP Response bodies based on a Regular Expression, similarly to the "Grep - Extract" feature in Burp Intruder but will work on any Responses. This can be helpful when trying to perform manual reconnaissance or building an injection in Burp Repeater, without having to scroll through multiple matches in the Response search results.

The Regular Expression is defined per-request. It will extract the full match, and also highlight and extract any groups defined in the regex, and display them in a list on a new tab. Named groups can also be used for more detail in the Regular Expression. 

![screenshot](https://github.com/b4dpxl/Burp-ResponseGrepper/blob/master/screenshots/results_pane.png?raw=true)

This is a Python extension, so it needs jython to be configured.
See [here](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite)
