# pylint: disable=C0103,C0111,W0614

from __future__ import print_function

import ida_idaapi
from ida_hexrays import *

class CXorOptimizer(optinsn_t):
    def __init__(self):
        optinsn_t.__init__(self)

    def func(self, blk, ins, _optflags):
        if blk.mba.maturity != MMAT_GLBOPT1:
            return 0

        changed = 0

        #We do optimize instruction at level MMAT_GLBOPT1 only
        if ins.opcode == m_and and \
        ins.l.is_insn(m_bnot) and \
        ins.r.is_insn(m_or) and \
        ins.l.d.l.is_insn(m_and):
            subIns = ins.l.d.l.d
            if subIns.l == ins.r.d.l and subIns.r == ins.r.d.r:
                #Found match ~(a2 & a1) & (a2 | a1). Fix to xor
                l = mop_t(subIns.l)
                r = mop_t(subIns.r)
                ins.l = l
                ins.r = r
                ins.opcode = m_xor
                blk.mark_lists_dirty()
                changed += 1

        return changed

class xor_optimizer_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "xor optimizer"
    wanted_hotkey = ""
    comment = ""
    help = ""

    def __init__(self):
        self.optimizer = None

    def init(self):
        if init_hexrays_plugin():
            self.optimizer = CXorOptimizer()
            self.optimizer.install()
            print("Xor optimizer installed")
            return ida_idaapi.PLUGIN_KEEP

        return ida_idaapi.PLUGIN_SKIP

    def term(self):
        if self.optimizer:
            self.optimizer.remove()

    def run(self):
        pass

def PLUGIN_ENTRY():
    return xor_optimizer_plugin_t()
