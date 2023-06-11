#ifndef FUSION_HH
#define FUSION_HH 1

#include <glib.h>

#include "bt.hh"

static bool fusable(cs_insn *head, cs_insn *tail,
    // limit of reg read, reg write, imm, reg read+write, reg read+write+imm
    uint8_t limitr=2, uint8_t limitw=1, uint8_t limiti=-1, uint8_t limitrw=-1, uint8_t limitrwi=4,
    bool default_dep = false, bool relax = false
) {
    int nr=0, nw=0, ni=0; // num of read, write, imm
    bool dep = default_dep; // data dependency
    cs_x86 *hx86 = &head->detail->x86;
    cs_x86 *tx86 = &tail->detail->x86;

    // sum head's and tail's nr, nw, ni
    // c lang is to weak to express `for x86 in {hx86, tx86}`
    {cs_x86 *x86s[] = {hx86, tx86}; for (int i=0; i<2; i++) { cs_x86 *x86 = x86s[i];
        for (int opi=0; opi<x86->op_count; opi++) {
            cs_x86_op *op = &x86->operands[opi];
            if (op->type==X86_OP_REG || op->type==X86_OP_MEM) {
                if (op->access & CS_AC_READ) nr++;
                if (op->access & CS_AC_WRITE) nw++;
            }
            if (op->type==X86_OP_IMM) ni++;
        }
    }}

    // subtract nr by number of overlapped <head out gpr> and <tail in gpr>
    for (int hi=0; hi<hx86->op_count; hi++) {
        cs_x86_op *hop = &hx86->operands[hi]; // head operand
        if (hop->type != X86_OP_REG) continue;
        if (!(hop->access & CS_AC_WRITE)) continue;

        int hgpr = x86GPRidx(hop->reg); // head general purpose reg
        if (hgpr < 0) continue;

        for (int ti=0; ti<tx86->op_count; ti++) {
            cs_x86_op *top = &tx86->operands[ti]; // tail operand
            if (top->type != X86_OP_REG) continue;
            if (!(hop->access & CS_AC_READ)) continue;

            int tgpr = x86GPRidx(top->reg); // tail general purpose reg
            if (tgpr < 0) continue;

            if (hgpr == tgpr){
                nr--;
                dep = true;
            }
        }
    }

    bool head_write_eflags = hx86->eflags & (0ULL
        |X86_EFLAGS_MODIFY_AF|X86_EFLAGS_MODIFY_CF|X86_EFLAGS_MODIFY_SF|X86_EFLAGS_MODIFY_ZF|X86_EFLAGS_MODIFY_PF|X86_EFLAGS_MODIFY_OF
        |X86_EFLAGS_RESET_AF |X86_EFLAGS_RESET_CF |X86_EFLAGS_RESET_SF |X86_EFLAGS_RESET_ZF |X86_EFLAGS_RESET_PF |X86_EFLAGS_RESET_OF
        |X86_EFLAGS_SET_AF   |X86_EFLAGS_SET_CF   |X86_EFLAGS_SET_SF   |X86_EFLAGS_SET_ZF   |X86_EFLAGS_SET_PF   |X86_EFLAGS_SET_OF
    );
    bool tail_read_eflags = tx86->eflags & (0ULL
        |X86_EFLAGS_TEST_AF  |X86_EFLAGS_TEST_CF  |X86_EFLAGS_TEST_SF  |X86_EFLAGS_TEST_ZF  |X86_EFLAGS_TEST_PF  |X86_EFLAGS_TEST_OF
    );
    if (head_write_eflags && tail_read_eflags) {
        dep = true;
    }

    if (dep && nr<=limitr && nw<=limitw && ni<=limiti && (nr+nw)<=limitrw && (nr+nw+ni)<=limitrwi)
        return true;
    else
        return false;
}

#endif /* FUSION_HH */
