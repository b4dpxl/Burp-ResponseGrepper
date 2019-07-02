"""
Adds a tab to BurpSuite responses to extract the matches of a regular expression

History:
0.2 - Added a default regex ".*canary.*" and made the regex case insensitive
1.0 - Custom tab pane with HTML styling and per-request regex

"""
__author__ = "b4dpxl"
__license__ = "GPL"
__version__ = "1.0"

import re
import sys
import traceback

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IContextMenuFactory
from burp import ITextEditor

# Java imports
from javax import swing 
from javax.swing.text import html
from java.awt import BorderLayout


NAME = "Response Grepper"


def html_encode(text):
    """Produce entities within text."""
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(html_escape_table.get(c,c) for c in text)


def fix_exception(func):
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except:
            sys.stderr.write('\n\n*** PYTHON EXCEPTION\n')
            traceback.print_exc(file=sys.stderr)
            raise
    return wrapper


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # for error handling
        sys.stdout = callbacks.getStdout()  
        sys.stderr = callbacks.getStderr()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(NAME)
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable): 
        # print(dir(controller))
        return ResponseGrepperTab(self, controller, editable)
        

class ResponseGrepperTab(IMessageEditorTab):

    @fix_exception
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable

        # self._txtInput = extender._callbacks.createTextEditor()
        # self._txtInput.setEditable(editable)
        self.results = MyEditor()
        # print(controller.toString())

    def getTabCaption(self):
        return NAME

    def getUiComponent(self):
        return self.results.getComponent()

    @fix_exception
    def isEnabled(self, content, isRequest):
        if isRequest:
            return False

        return True

    @fix_exception
    def setMessage(self, content, isRequest):
        if content is None or isRequest:
            self.results.setText(None)
            self.results.setEditable(False)
            return

        r = self._helpers.analyzeResponse(content)
        msg = content[r.getBodyOffset():].tostring()

        self.results.setMessage(msg)

        self.results.setEditable(False)
        self._currentMessage = content

    def getMessage(self): 
        return self._currentMessage

    def isModified(self):
        return self.results.isTextModified()

    def getSelectedData(self):
        return self.results.getSelectedText()


class MyEditor(ITextEditor):

    _regex_fail = False
    _str_error = None
    _msg = None
    _rex = None

    @fix_exception
    def __init__(self):
        self.tab = swing.JPanel(BorderLayout())

        box = swing.Box.createHorizontalBox()
        box.add(swing.JLabel("Regular Expression"))
        # vert.add(box)
        # box = swing.Box.createHorizontalBox()
        self.re_box = swing.JTextField(100)
        box.add(self.re_box)
        box.add(swing.JButton('Update', actionPerformed=self._update_rex))
        box.add(swing.JButton('?', actionPerformed=self._help))

        self.tab.add(box, BorderLayout.NORTH)

        box = swing.Box.createHorizontalBox()
        self.results = swing.JEditorPane()
        self.results.setEditable(False)
        kit = html.HTMLEditorKit()
        ss = kit.getStyleSheet()
        ss.addRule(".error {color: #CC0000;}")
        ss.addRule("li {color: #000000;}")
        ss.addRule(".result {color: #006600; font-family: monospace;}")
        ss.addRule(".subresult {color: #000099; font-family: monospace;}")
        ss.addRule(".re {color: #000099; font-weight: bold;}")

        self.results.setEditorKit(kit)
        doc = kit.createDefaultDocument()
        self.results.setDocument(doc)
        self.results.setText("<em>yeet</em>")

        scroller = swing.JScrollPane(self.results)
        box.add(scroller)
        self.tab.add(box, BorderLayout.CENTER)

    def _help(self, event):
        swing.JOptionPane.showMessageDialog(None, """All matching subgroups will also be extracted. For example, to extract the value between 2 DIV tags: 

<div class='test'>(.*?)</div>

Named groups can also be used INSTEAD (don't mix named and unnamed). For example:

<div class='test'>(?P<tag>.*?)</div>""")

    def getComponent(self):
        return self.tab

    def getSelectedText(self):
        return None

    def getSelectionBounds(self):
        return None

    def getText(self):
        return None

    def setEditable(self, editable):
        return

    def isTextModified(self):
        return False

    def setSearchExpression(self, str):
        return

    @fix_exception
    def setMessage(self, msg):
        self._msg = msg
        self._update()

    def _update_rex(self, event):
        if self.re_box.getText() is None:
            self._rex = None
        else:
            x = self.re_box.getText().strip()
            if len(x):
                self._rex = x
            else:
                self._rex = None
        self._update()

    @fix_exception
    def _update(self):

        if self._rex is None:
            self.results.setText("<b class='error'>Regex not set</b>")

        else:
            try:
                if re.search(self._rex, self._msg, re.IGNORECASE):
                    out = "<ol>"
                    res = re.finditer(self._rex, self._msg, re.IGNORECASE)
                    c = 0
                    for m in res:
                        c += 1

                        g = m.groups()
                        ret = ""
                        if len(g):
                            prev_end = m.start(0)
                            for r in range(1, len(g) + 1):
                                s = m.start(r)
                                e = m.end(r)
                                # print(prev_end, s)
                                ret += self._msg[prev_end:s] + "~~@@~~" + g[r - 1] + "~~@@@~~"
                                prev_end = e
                            ret += self._msg[prev_end:m.end(0)]
                        else:
                            ret = m.group(0)

                        out += "<li><span class='result'>" + html_encode(ret).replace("~~@@~~", "<span class='re'>")\
                            .replace("~~@@@~~", "</span>") + "</span><ol>"

                        if len(g):
                            if len(m.groupdict()) > 0:
                                # named groups
                                for g in m.groupdict():
                                    out += "<li><b>{}</b>: <span class='subresult'>{}</span></li>"\
                                        .format(g, html_encode(m.groupdict()[g]))

                            else:
                                for g in m.groups():
                                    out += "<li><span class='subresult'>{}</span></li>".format(g)

                        out += "</ol></li>"

                    out += "</ol>"

                    self.results.setText(
                        "Found <b>{}</b> match(es) for regex: <span class='re'>{}</span>".format(c, self._rex) + out
                        )

                else:
                    self.results.setText("No Matches for regex: {}".format(self._rex))

            except re.error  as e:
                self.results.setText(
                    "<b class='error'>Error parsing regex:<br /><span class='re'>{}</span><br /><br /><em>{}</em><b>"
                        .format(self._rex, str(e))
                )

