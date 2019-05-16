import json
import re
import sys
import traceback

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import IContextMenuFactory


# Java imports
from javax.swing import JMenuItem, JOptionPane
from java.util import List, ArrayList

NAME = "Response Grepper"

REGEX_CONTEXT_MENU = "{}: Set regex".format(NAME)
# Menu items
ENABLE_TAB_MENU_ITEMS = {
  True:  "{}: Tab only present on match".format(NAME),
  False: "{}: Tab always present".format(NAME)
}
_force_tab = False

_target_regex = None


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        # for error handling
        sys.stdout = callbacks.getStdout()  
        sys.stderr = callbacks.getStderr()

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(NAME)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerContextMenuFactory(self)

    def createNewInstance(self, controller, editable): 
        return ResponseGrepperTab(self, controller, editable)
        
    def createMenuItems(self, IContextMenuInvocation):
        global _force_tab
        menuItemList = ArrayList()
        menuItemList.add(JMenuItem(ENABLE_TAB_MENU_ITEMS[_force_tab], actionPerformed = self.onToggleTab))
        menuItemList.add(JMenuItem(REGEX_CONTEXT_MENU, actionPerformed = self.onUpdateRegex))
        return menuItemList

    def onToggleTab(self, event):
        global _force_tab
        _force_tab = not _force_tab

    def onUpdateRegex(self, event):
        global _target_regex
        res = JOptionPane.showInputDialog(None, """Set the Regex. All matching subgroups will also be extracted. For example, to extract the value between 2 DIV tags: 

<div class='test'>(.*?)</div>

Named groups can also be used INSTEAD (don't mix named and unnamed). For example:

<div class='test'>(?P<tag>.*?)</div>

""", _target_regex).strip()
        if res is not None:
            _target_regex = res


class ResponseGrepperTab(IMessageEditorTab):

    _regex_fail = False
    _str_error = None

    def fix_exception(func):
        def wrapper(self, *args, **kwargs):
            try:
                return func(self, *args, **kwargs)
            except:
                sys.stderr.write('\n\n*** PYTHON EXCEPTION\n')
                traceback.print_exc(file=sys.stderr)
                raise
        return wrapper

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable

        self._txtInput = extender._callbacks.createTextEditor()
        self._txtInput.setEditable(editable)

    def getTabCaption(self):
        return NAME

    def getUiComponent(self):
        return self._txtInput.getComponent()

    @fix_exception
    def isEnabled(self, content, isRequest):
        if isRequest:
            return False

        self._regex_fail = False    
        self._str_error = None

        try:
            r = self._helpers.analyzeResponse(content)
            msg = content[r.getBodyOffset():].tostring()
            return re.search(_target_regex, msg) or _force_tab
        except Exception as e:
            self._str_error = str(e)
            self._regex_fail = True
            return True
        
    @fix_exception
    def setMessage(self, content, isRequest):
        if content is None or isRequest:
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
            return

        r = self._helpers.analyzeResponse(content)
        msg = content[r.getBodyOffset():].tostring()

        if _target_regex is None:
            self._txtInput.setText("Regex not set. Use context menu '{}'".format(REGEX_CONTEXT_MENU))

        elif self._regex_fail:
            self._txtInput.setText("Error parsing regex:\n{}\n\n{}".format(_target_regex, self._str_error))

        else:
            if re.search(_target_regex, msg):
                out = ""
                matches = []
                res = re.finditer(_target_regex, msg)
                c = 0
                for m in res:
                    c += 1

                    out += "\n\n{:>15}] {}\n".format("Match #{}".format(c), m.group(0))
                    c2 = 0
                    if len(m.groupdict()) > 0:
                        # named groups
                        for g in m.groupdict():
                            out += "{:>15}] {}\n".format("Group #{}".format(g), m.groupdict()[g])

                    else:
                        for g in m.groups():
                            c2 += 1
                            out += "{:>15}] {}\n".format("Group #{}".format(chr(96+c2)), g)

                self._txtInput.setText(
                    "Found {} match(es) for regex: {}".format(c, _target_regex) + out
                    )

            else:
                self._txtInput.setText("No Matches for regex: {}".format(_target_regex))


        self._txtInput.setEditable(self._editable)
        self._currentMessage = content        

    def getMessage(self): 
        return self._currentMessage

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()



