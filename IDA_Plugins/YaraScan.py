# pylint default of HTC, disable some noisy messages :D
# pylint: disable=C0301,C0103,C0111

# References:
#   https://github.com/polymorf/findcrypt-yara
#   https://github.com/OALabs/FindYara

# -*- coding: utf-8 -*-

#==============================================================================
#
# All credit to David Berard (@_p0ly_) https://github.com/polymorf/findcrypt-yara
#
# This plugin is simply a copy of his excellent findcrypt-yara plugin only expanded
# use allow searching for any yara rules.
#
#  ____ __ __  __ ____   _  _  ___  ____   ___
# ||    || ||\ || || \\  \\// // \\ || \\ // \\
# ||==  || ||\\|| ||  ))  )/  ||=|| ||_// ||=||
# ||    || || \|| ||_//  //   || || || \\ || ||
#
# IDA plugin for Yara scanning... find those Yara matches!
#
# Add this this file to your IDA "plugins" directory
# Activate using Ctrl+Alt+Y or Edit->Plugins->YaraScan
#
# Update:
#    29/05/2020 - HTC (VinCSS) - Add yara directory scan, multi Yara files scan
#                              - Fix some bugs in action handlers and some bugs :D
#                              - Add apply names and comments in chooser
#==============================================================================

from __future__ import print_function

import os
import operator
import string
import yara
import idc
import idaapi
import idautils
import ida_bytes
import ida_diskio
import ida_kernwin

from PyQt5 import QtWidgets

VERSION = "1.2.1"

try:
    class IDAMenuContext(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(cls):
            return cls.__name__

        @classmethod
        def get_label(cls):
            return cls.label

        @classmethod
        def register(cls, plugin, label):
            cls.plugin = plugin
            cls.label = label
            instance = cls()
            return idaapi.register_action(idaapi.action_desc_t(
                cls.get_name(),         # Name. Acts as an ID. Must be unique.
                instance.get_label(),   # Label. That's what users see.
                instance                # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(cls):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(cls.get_name())

        @classmethod
        def activate(cls, ctx):
            # dummy method
            return 1

        @classmethod
        def update(cls, ctx):
            return idaapi.AST_ENABLE_FOR_WIDGET

    class FileScanCtx(IDAMenuContext):
        def activate(self, ctx):
            self.plugin.files_scan()
            return 1

    class DirScanCtx(IDAMenuContext):
        def activate(self, ctx):
            self.plugin.dir_scan()
            return 1

except Exception:
    pass

# Add comment or name to the head address of addr
def add_name_cmt(addr, new_name_cmt, set_cmt):
    if new_name_cmt is None:
        return 0

    new_name_cmt = new_name_cmt.strip()
    if len(new_name_cmt) == 0:
        return 0

    addr = idc.get_item_head(addr)

    if set_cmt:
        old_cmt = idc.get_cmt(addr, 0)
        if old_cmt: # already have comment
            if new_name_cmt in old_cmt:
                cmt = old_cmt
            else:
                cmt = old_cmt + "\n" + new_name_cmt
        else:
            cmt = new_name_cmt
        ret = idc.set_cmt(addr, cmt, 0)
    else:
        ret = idc.set_name(addr, new_name_cmt, idaapi.SN_FORCE)

    return ret

# HTC - unused function !!??
# but it is the author's original code,
# so I can't delete :(
def lrange(num1, num2=None, step=1):
    op = operator.__lt__
    if num2 is None:
        num1, num2 = 0, num1
    if num2 < num1:
        if step > 0:
            num1 = num2
        op = operator.__gt__
    elif step < 0:
        num1 = num2
    while op(num1, num2):
        yield num1
        num1 += step

# Handler for assign names/comment
# Add by HTC
# 0, 1, 2, 3, 4, 5 is assign name or comment
COMMAND_HANDERS = [["choose:nam_from_rule_name", "Apply Name from Rule Name", 0],
                   ["choose:comment_from_rule_name", "Apply Comment from Rule Name", 1],
                   ["choose:name_from_rule_description", "Apply Name from Rule Description", 2],
                   ["choose:comment_from_rule_description", "Apply Comment from Rule Description", 3],
                   ["choose:name_from_rule_metaname", "Apply Name from Rule Meta Name", 4],
                   ["choose:comment_from_rule_metaname", "Apply Comment from Rule Meta Name", 5]]

class chooser_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, chooser, items, make_name_cmt):
        ida_kernwin.action_handler_t.__init__(self)
        self.chooser = chooser
        self.items = items
        self.make_name_cmt = make_name_cmt

    def activate(self, ctx):
        for idx in ctx.chooser_selection:
            if self.make_name_cmt == 0:    # Name Rule
                add_name_cmt(self.items[idx][0], self.items[idx][3], False)
            elif self.make_name_cmt == 1:  # Comment Rule
                add_name_cmt(self.items[idx][0], self.items[idx][3], True)
            elif self.make_name_cmt == 2:  # Name Description
                add_name_cmt(self.items[idx][0], self.items[idx][4], False)
            elif self.make_name_cmt == 3:  # Comment Description
                add_name_cmt(self.items[idx][0], self.items[idx][4], True)
            elif self.make_name_cmt == 4:  # Name Meta Name
                add_name_cmt(self.items[idx][0], self.items[idx][5], False)
            elif self.make_name_cmt == 5:  # Comment Meta Name
                add_name_cmt(self.items[idx][0], self.items[idx][5], True)
            else:
                return  # Something wrong here :(

        self.chooser.Refresh()


    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ida_kernwin.is_chooser_widget(ctx.widget_type) \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


class YaraScanResultChooser(idaapi.Choose):
    def __init__(self, title, items):
        idaapi.Choose.__init__(
            self,
            title,
            [
                ["Address", idaapi.Choose.CHCOL_HEX|10],
                ["Current Name", idaapi.Choose.CHCOL_PLAIN|10],
                ["Rule File", idaapi.Choose.CHCOL_PLAIN|10],
                ["Rule Name", idaapi.Choose.CHCOL_PLAIN|10],
                ["Rule Description", idaapi.Choose.CHCOL_PLAIN|25],
                ["Rule Meta Name", idaapi.Choose.CHCOL_PLAIN|10],
                ["String", idaapi.Choose.CHCOL_PLAIN|25],
                ["Type", idaapi.Choose.CHCOL_PLAIN|5],
            ],
            flags=idaapi.Choose.CH_CAN_REFRESH | idaapi.Choose.CH_MULTI   # HTC - allow multiselect to apply names/comments
        )
        self.items = items

    def OnSelectLine(self, n):
        idc.jumpto(self.items[n[0]][0])

    def OnGetLine(self, n):
        res = self.items[n]
        res = [idc.atoa(res[0]), res[1], res[2], res[3], res[4], res[5], str(res[6]), res[7]]
        return res

    def OnRefresh(self, indices):
        # Update current name from IDA to self.items
        for n in indices:
            name = idc.get_name(idc.get_item_head(self.items[n][0]), idc.GN_DEMANGLED)
            if name != self.items[n][1]:
                self.items[n][1] = name

        return [idaapi.Choose.ALL_CHANGED] + indices

    def OnGetSize(self):
        return len(self.items)

    def OnPopup(self, widget, popup_handle):
        for cmd in COMMAND_HANDERS:
            desc = ida_kernwin.action_desc_t(cmd[0],    # The action name
                                             cmd[1],    # The action text.
                                             chooser_handler_t(self, self.items, cmd[2])) # The action handler.
            ida_kernwin.attach_dynamic_action_to_popup(widget, popup_handle, desc)


#--------------------------------------------------------------------------
# Plugin
#--------------------------------------------------------------------------

g_initialized = False

class YaraScan_Plugin_t(idaapi.plugin_t):
    flags = 0   # idaapi.PLUGIN_UNL | idaapi.PLUGIN_HIDE
    comment = "Yara scan plugin for IDA Pro (using yara framework)"
    help = "Still todo..."
    wanted_name = "YaraScan"
    wanted_hotkey = "Ctrl-Shift-Y"

    # Private fields
    yara_dir = ""

    def init(self):
        global g_initialized

        self.yara_dir = self.get_default_yara_dir()

        # register popup menu handlers
        try:
            FileScanCtx.register(self, "Scan with Yara files")
            DirScanCtx.register(self, "Scan with a directory of Yara files")
        except Exception:
            pass

        if g_initialized is False:
            g_initialized = True

            #
            # populating action menus
            #
            # FileScan
            action_desc = idaapi.action_desc_t(FileScanCtx.get_name(),  # The action name. This acts like an ID and must be unique
                                               FileScanCtx.get_label(), # The action text.
                                               FileScanCtx,             # The action handler.
                                               None,                    # Optional: the action shortcut
                                               None,                    # Optional: the action tooltip (available in menus/toolbar)
                                               0)                       # Optional: the action icon (shows when in menus/toolbars) use numbers 1-255

            # Register the action
            idaapi.register_action(action_desc)
            idaapi.attach_action_to_menu("Search/YaraScan/", FileScanCtx.get_name(), idaapi.SETMENU_APP)

            # DirScan
            action_desc = idaapi.action_desc_t(DirScanCtx.get_name(),
                                               DirScanCtx.get_label(),
                                               DirScanCtx,
                                               None,
                                               None,
                                               0)

            idaapi.register_action(action_desc)
            idaapi.attach_action_to_menu("Search/YaraScan/", DirScanCtx.get_name(), idaapi.SETMENU_APP)

            ## Print a nice header
            print("\n" + "-" * 60)
            print("* YaraScan v{0} by HTC (VinCSS)                          *".format(VERSION))
            print("* All credit to David Berard (@_p0ly_) for the code!       *")
            print("* Add the yara multifiles, directory scan, chooser by HTC  *")
            print("* This is a slightly modified version of findcrypt-yara    *")
            print("* YaraScan shortcut key is Ctrl-Shift-Y                    *")
            print("-" * 60)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if arg == 0:
            self.files_scan()
        else:
            self.dir_scan()

    def term(self):
        if g_initialized:
            FileScanCtx.unregister()
            DirScanCtx.unregister()

        print("YaraScan plugin terminated")

    @staticmethod
    def toVirtualAddress(offset, segments):
        va_offset = 0
        for seg in segments:
            if seg[1] <= offset < seg[2]:
                va_offset = seg[0] + (offset - seg[1])
        return va_offset

    @staticmethod
    def get_default_yara_dir():
        yara_dir = os.path.join(ida_diskio.get_user_idadir(), "yara")
        if not os.path.exists(yara_dir):
            try:
                os.makedirs(yara_dir, 0o755)
            except OSError:
                print("Could not create default yara directory %s" % yara_dir)
        return yara_dir

    def yarascan(self, memory, offsets, yara_file):
        print("Yara scanning with file %s..." % yara_file)

        try:
            rules = yara.compile(yara_file)
        except Exception as e:
            print("ERROR: Cannot compile Yara file %s" % yara_file)
            print(e.args[-1])
            return None

        # Cache, get filename only
        yara_file = os.path.basename(yara_file)

        values = list()
        matches = rules.match(data=memory)

        for rule_match in matches:
            # Cache meta_desc and meta_name outside loop for faster
            meta_desc = rule_match.meta.get("description", "")
            meta_name = rule_match.meta.get("name", "")
            for match in rule_match.strings:
                match_string = match[2]
                match_type = 'ascii string'
                if not all(c in string.printable for c in match_string):
                    if all(c in string.printable + '\x00' for c in match_string) and ('\x00\x00' not in match_string):
                        match_string = match_string.decode('utf-16')
                        match_type = 'wide string'
                    else:
                        match_string = " ".join("{:02X}".format(ord(c)) for c in match_string)
                        match_type = 'binary'
                ea = self.toVirtualAddress(match[0], offsets)
                value = [ea,
                         idc.get_name(ea, idc.GN_DEMANGLED),
                         yara_file,
                         rule_match.rule,
                         meta_desc,
                         meta_name,
                         match_string,
                         match_type]
                values.append(value)

        return values

    @staticmethod
    def _get_memory():
        result = bytearray()
        segment_starts = [ea for ea in idautils.Segments()]
        offsets = []
        start_len = 0
        for start in segment_starts:
            end = idc.get_segm_attr(start, idc.SEGATTR_END)
            result += ida_bytes.get_bytes(start, end - start)
            offsets.append((start, start_len, len(result)))
            start_len = len(result)
        return bytes(result), offsets

    def files_scan(self):
        yara_files, _ = QtWidgets.QFileDialog.getOpenFileNames(None, "Choose Yara files...",
                                                               self.yara_dir,
                                                               "*.yar *.yara *.rules")
        if yara_files is None or len(yara_files) == 0:
            return

        print(">>> Start yara scanning...")

        memory, offsets = self._get_memory()

        values = []
        all_values = []
        for the_file in yara_files:
            the_file = str(the_file)
            values = self.yarascan(memory, offsets, the_file)
            if values:
                all_values.extend(values)

        if len(all_values) > 0:
            c = YaraScanResultChooser("YaraScan results", all_values)
            c.Show()
        else:
            print("No scanning results")

        print(">>> End yara scanning.")

    def dir_scan(self):
        sel_dir = str(QtWidgets.QFileDialog.getExistingDirectory(None, "Choose Yara directory...",
                                                                 self.yara_dir,
                                                                 QtWidgets.QFileDialog.ShowDirsOnly))
        if len(sel_dir) == 0:
            return

        self.yara_dir = sel_dir # save for later browse
        yara_files = []

        ask_confirm = False
        ret = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Do you want to confirm with every Yara file ?")
        if ret == ida_kernwin.ASKBTN_CANCEL:
            return
        elif ret == ida_kernwin.ASKBTN_YES:
            ask_confirm = True

        for root, _directories, files in os.walk(sel_dir):
            for file in files:
                the_file = os.path.join(root, file)
                _, ext = os.path.splitext(the_file)
                if ext.upper().startswith(".YAR"):
                    if ask_confirm:
                        # Confirm cai cho chac ;)
                        ret = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, "Do you want to scan with file %s" % the_file)
                        if ret == ida_kernwin.ASKBTN_CANCEL:
                            return
                        elif ret == ida_kernwin.ASKBTN_YES:
                            yara_files.append(the_file)
                    else:
                        yara_files.append(the_file)

        # Reach here, check the list
        if len(yara_files) == 0:
            print("No yara files to scan !")
            return

        print(">>> Start yara scanning...")

        values = []
        all_values = []
        memory, offsets = self._get_memory()
        for the_file in yara_files:
            values = self.yarascan(memory, offsets, the_file)
            if values:
                all_values.extend(values)

        if len(all_values) > 0:
            c = YaraScanResultChooser("YaraScan results", all_values)
            c.Show()
        else:
            print("No scanning results")

        print(">>> End yara scanning.")


# register IDA plugin
def PLUGIN_ENTRY():
    return YaraScan_Plugin_t()
