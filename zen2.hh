#ifndef ZEN2_HH
#define ZEN2_HH

#include "bt.hh"

class Zen2: public BT {
private:
    int64_t cmp_jmp_fusion_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if ((head->id==X86_INS_CMP || head->id==X86_INS_TEST) && isJcc(tail->id)) {
                opt -= 1 * count;
            }
        }
        excess_by_isa_feat[MY_FEAT_CMPJMP_FUSION_OPT] += opt;
        return opt;
    }
    int64_t opt(TBCount *tbcnt) override {
        int64_t opt = 0;
        opt += BT::opt(tbcnt);
        opt += cmp_jmp_fusion_opt_sum_ex(tbcnt);

        return opt;
    }

protected:
    int inflt_extra_call(PCCount *pccnt) {
        int mem = 0;

        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {
                mem = 4;
                break;
            }
        }

        if (mem) {
            excess_by_isa_feat[MY_FEAT_MEM] += mem * count;
            pccnt->feats[MY_FEAT_MEM] += mem;
        }

        return mem;
    }

    int inflt_extra_ret(PCCount *pccnt) {
        int immload = 0;

        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_IMM) {
                immload = 1; // if ret_i then extra inflate
                break;
            }
        }

        excess_by_isa_feat[MY_FEAT_IMMLOAD] += immload * count;
        pccnt->feats[MY_FEAT_IMMLOAD] += immload;

        return immload;
    }

    int inflt_extra_pop(PCCount *pccnt) {
        int mem = 0;

        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {
                mem = 1;
                break;
            }
        }

        excess_by_isa_feat[MY_FEAT_MEM] += mem * count;
        pccnt->feats[MY_FEAT_MEM] += mem;

        return mem;
    }
    int inflt_extra_push(PCCount *pccnt) {
        int mem = 0;
        int inflt = 0;

        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {
                mem = 1;
                break;
            } else if (op->type == X86_OP_REG && op->reg == X86_REG_RSP) {
                inflt = 1;
                break;
            }
        }

        excess_by_isa_feat[MY_FEAT_MEM] += mem * count;
        pccnt->feats[MY_FEAT_MEM] += mem;

        return mem + inflt;
    }

public:
    Zen2() {
        indirect_jmp_inflt = 0;
        indirect_call_inflt = 0;
    }

    BaseExtra inflt(PCCount *pccnt) override {
        cs_insn *insn = pccnt->insn;
        x86_insn id = x86_insn(insn->id);

        // calculate base
        switch (id) {
        case X86_INS_ADD: case X86_INS_SUB:
            return BaseExtra(1, 0);
        case X86_INS_AND: case X86_INS_OR: case X86_INS_XOR:
            return BaseExtra(1, 0);
        case X86_INS_CALL:
            return BaseExtra(2, inflt_extra_call(pccnt));
        case X86_INS_RET:
            return BaseExtra(1, inflt_extra_ret(pccnt));
        case X86_INS_CMOVNP: case X86_INS_CMOVP:
        case X86_INS_CMOVA:  case X86_INS_CMOVBE:
        case X86_INS_CMOVAE: case X86_INS_CMOVB:
        case X86_INS_CMOVNO: case X86_INS_CMOVO:
        case X86_INS_CMOVGE: case X86_INS_CMOVL:
        case X86_INS_CMOVG:  case X86_INS_CMOVLE:
        case X86_INS_CMOVE: case X86_INS_CMOVNE:
        case X86_INS_CMOVS: case X86_INS_CMOVNS:
            return BaseExtra(1, 0);
        case X86_INS_CMP: case X86_INS_TEST:
            return BaseExtra(1, 0);
        // TODO: r8/m8 inflt=1
        case X86_INS_DIV: case X86_INS_IDIV:
            return BaseExtra(2, 0); 
        case X86_INS_JAE: case X86_INS_JA:  case X86_INS_JBE: case X86_INS_JB:
        case X86_INS_JE:  case X86_INS_JGE: case X86_INS_JG:  case X86_INS_JLE:
        case X86_INS_JL:  case X86_INS_JNE: case X86_INS_JNO: case X86_INS_JNP:
        case X86_INS_JNS: case X86_INS_JO:  case X86_INS_JP:  case X86_INS_JS:
            return BaseExtra(1, 0);
        case X86_INS_JMP:
            return BaseExtra(1, 0);
        case X86_INS_LAHF:
            return BaseExtra(4, 0);
        // TODO: r16,[m] inflt=2
        case X86_INS_LEA:
            return BaseExtra(1, 0);
        case X86_INS_MOV: case X86_INS_MOVABS:
        case X86_INS_MOVSX: case X86_INS_MOVZX: case X86_INS_MOVSXD:
            return BaseExtra(1, 0);
        // TODO: ...
        case X86_INS_MUL:
            return BaseExtra(2, 0);
        case X86_INS_MULX:
            return BaseExtra(2, 0);
        case X86_INS_NOP:
            return BaseExtra(1, 0);
        case X86_INS_POP:
            return BaseExtra(1, inflt_extra_pop(pccnt));
        case X86_INS_PUSH:
            return BaseExtra(1, inflt_extra_push(pccnt));

        // new findings
        case X86_INS_SHLD: case X86_INS_SHRD:
            return BaseExtra(7, 0);


        case X86_INS_COMISS: case X86_INS_COMISD:
        case X86_INS_UCOMISS: case X86_INS_UCOMISD:
            return BaseExtra(2, 0);
        case X86_INS_ADDSS: case X86_INS_ADDSD:
        case X86_INS_SUBSS: case X86_INS_SUBSD:
            return BaseExtra(1, 0);
        case X86_INS_CVTDQ2PD :
            return BaseExtra(1, 0);
        case X86_INS_CVTDQ2PS :
            return BaseExtra(1, 0);
        case X86_INS_CVTPD2PS :
            return BaseExtra(1, 0);
        case X86_INS_CVTPS2PD :
            return BaseExtra(1, 0);
        case X86_INS_CVTSD2SS :
            return BaseExtra(1, 0);
        case X86_INS_CVTSI2SD :
            return BaseExtra(2, 0);
        case X86_INS_CVTSI2SS :
            return BaseExtra(2, 0);
        case X86_INS_CVTSS2SD :
            return BaseExtra(2, 0);
        case X86_INS_DIVSS: case X86_INS_DIVPS:
        case X86_INS_DIVSD: case X86_INS_DIVPD:
            return BaseExtra(1, 0);
        case X86_INS_MOVAPD: case X86_INS_MOVAPS:
        case X86_INS_MOVSD: case X86_INS_MOVSS:
        case X86_INS_MOVUPD: case X86_INS_MOVUPS:
            return BaseExtra(1, 0);
        case X86_INS_MULPD: case X86_INS_MULPS:
        case X86_INS_MULSD: case X86_INS_MULSS:
            return BaseExtra(1, 0);

        default:
            return BaseExtra(-1, 0);
        }
    }

};

#endif
