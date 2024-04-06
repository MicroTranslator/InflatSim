#ifndef QEMU_HH
#define QEMU_HH

#include "bt.hh"
#include <capstone/capstone.h>
#include <capstone/x86.h>

class Qemu: public BT {
private:
    // 访存操作会导致上一条指令存2条左右cc_src,cc_dst, mem+= 3
    int mem_inflt_ex(PCCount *pccnt) override {
        int inflt = 0;
        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {

                // capstone bug: test not have mem/reg access
                if (insn->id == X86_INS_TEST) {
                    inflt++;
                    continue;
                }

                if (op->access & CS_AC_READ)
                    inflt+=3;
                if (op->access & CS_AC_WRITE)
                    inflt+=3;
            }
        }
        excess_by_isa_feat[MY_FEAT_MEM] += inflt * count;
        pccnt->feats[MY_FEAT_MEM] += inflt;
        return inflt;
    }

    int inflt_extra_default(PCCount *pccnt) override {
        // 默认对于所有的计算类指令
        int inflt = 0;  // 寄存器读写额外高1，由于寄存器可能在内存中，读reg需要load一次
        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_REG) {
                if (op->access & CS_AC_READ)
                    inflt += 1;
                if (op->access & CS_AC_WRITE)
                    inflt += 1;
            }
        }

        int mem = mem_inflt_ex(pccnt);  // read +1, write + 1
        int addr = addr_inflt_ex(pccnt);    // SIB: index || scale >1  +1. no disp!
        int immload = immload_inflt_ex(pccnt);  // disp + imm, 大于编码长度12， + 1
        int subreg = subreg_inflt_ex(pccnt);    // mem(base+index) + reg, low/high/16, +1
        return mem + addr + immload + subreg + inflt;
    }


public:
    Qemu() {
        indirect_jmp_inflt = 10;   // 间接跳转直接100, 其实会用到helper
        indirect_call_inflt = 1;    // 间接call = 直接call

    }

    BaseExtra inflt(PCCount *pccnt) override {
        cs_insn *insn = pccnt->insn;
        int base = 0, extra = 0;
        x86_insn id = x86_insn(insn->id);

        // calculate base and extra
        switch (id) {
            case X86_INS_ADD: case X86_INS_SUB:
            case X86_INS_AND: case X86_INS_OR: case X86_INS_XOR:
                return BaseExtra(1, inflt_extra_default(pccnt));
            case X86_INS_MOV: case X86_INS_MOVSX: case X86_INS_MOVSXD: case X86_INS_MOVZX: case X86_INS_MOVABS:
            case X86_INS_MOVSS: case X86_INS_MOVSD:
                return BaseExtra(1, inflt_extra_default(pccnt));
            case X86_INS_CALL:
                return BaseExtra(10, inflt_extra_jmp(pccnt, indirect_call_inflt));
            case X86_INS_RET:
                return BaseExtra(10, 0);   // call,  ret 均为100
            case X86_INS_PUSH: case X86_INS_POP:
                return BaseExtra(5, inflt_extra_default(pccnt));    // todo: push, pop暂时为5
            case X86_INS_JAE: case X86_INS_JB:
            case X86_INS_JE:  case X86_INS_JGE: case X86_INS_JG:
            case X86_INS_JNE: case X86_INS_JNO:
            case X86_INS_JNS:  case X86_INS_JS:
                return BaseExtra(10, inflt_extra_jmp(pccnt, indirect_jmp_inflt));     // 假定直接跳转要10条吧
            case X86_INS_JO: case X86_INS_JBE: case X86_INS_JA: 
            case X86_INS_JP: case X86_INS_JL: case X86_INS_JLE:
                return BaseExtra(10, inflt_extra_jmp(pccnt, indirect_jmp_inflt));   // 这6类为50
            case X86_INS_ADDPS: case X86_INS_ADDPD: case X86_INS_SUBPS: case X86_INS_SUBPD:
                return BaseExtra(5, inflt_extra_default(pccnt));  // add vec
                // return BaseExtra(150, inflt_extra_default(pccnt));  // add vec
            case X86_INS_MOVUPS: case X86_INS_MOVUPD: case X86_INS_MOVAPS: case X86_INS_MOVAPD:
                return BaseExtra(8, inflt_extra_default(pccnt));  // mov vec = 8
            case X86_INS_MULSD: case X86_INS_MULSS: case X86_INS_MULPD: case X86_INS_MULPS:
            case X86_INS_DIVSD: case X86_INS_DIVSS: case X86_INS_DIVPD: case X86_INS_DIVPS:
                return BaseExtra(5, inflt_extra_default(pccnt));
                // return BaseExtra(50, inflt_extra_default(pccnt));
            case X86_INS_ADDSS: case X86_INS_ADDSD:
            case X86_INS_SUBSS: case X86_INS_SUBSD:
                return BaseExtra(5, inflt_extra_default(pccnt));  // add single float = 110
                // return BaseExtra(80, inflt_extra_default(pccnt));
            default:
                return BT::inflt(pccnt);
        }

        return BaseExtra(base, extra);
    }


};



#endif // QEMU_HH