#ifndef IDEAL_HH
#define IDEAL_HH 1

#include "bt.hh"
#include "fusion.hh"

class Ideal: public BT {
private:
    static const int imm_max_encode_len = 12;
    static const int disp_max_encode_len = 8;

    // arm 有ldr指令，对于base + index 可以不膨胀
    int addr_inflt(const x86_op_mem *mem) override {
        return mem->scale>1;
    }

    // exagear 对于load (pc + imm), 有优化, 不进行immload膨胀
    // pc+imm 可以在编译时知道，并放在基本块开头的立即数表中
    int immload_inflt_ex(PCCount *pccnt) override {
        int immload = BT::immload_inflt_ex(pccnt);  // 先用基类的
        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
                immload = 0;   // pc + imm, 优化了
            }
        }
        return immload;
    }

    int subreg_inflt(x86_reg r) override {
        return 0;
    }
    bool is_subreg(x86_reg r) override {
        return false;
    }
    int subreg_inflt_ex(PCCount *pccnt) override {
        return 0;
    }

    int64_t fusion_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;

        for (int i=1; i<tbcnt->n_insns; i++) {
            cs_insn *head = tbcnt->cs_insns[i-1];
            cs_insn *tail = tbcnt->cs_insns[i];
            if (fusable(head, tail)) {
                opt -= 1 * tbcnt->count;
                i++;
            }
        }

        excess_by_isa_feat[MY_FEAT_FUSION_OPT] += opt;
        return opt;
    }

    int64_t opt(TBCount *tbcnt) override {
        int64_t opt = 0;
        opt += BT::opt(tbcnt);
        pushpop_esp_opt_sum_ex(tbcnt);  // 只统计，不放入总的
        opt += immload_opt_sum_ex(tbcnt); // ideal可以立即数优化
        opt += addr_opt_sum_ex(tbcnt);
        opt += fusion_opt_sum_ex(tbcnt);
        return opt;
    }

public:
    Ideal() {
        indirect_jmp_inflt = 12;
        indirect_call_inflt = 8;
    }

    BaseExtra inflt(PCCount *pccnt) override {
        cs_insn *insn = pccnt->insn;
        x86_insn id = x86_insn(insn->id);
        switch (id) {
        case X86_INS_JAE: case X86_INS_JA:  case X86_INS_JBE: case X86_INS_JB:
        case X86_INS_JE:  case X86_INS_JGE: case X86_INS_JG:  case X86_INS_JLE:
        case X86_INS_JL:  case X86_INS_JNE: case X86_INS_JNO: case X86_INS_JNP:
        case X86_INS_JNS: case X86_INS_JO:  case X86_INS_JP:  case X86_INS_JS:
            return BaseExtra(1, 0);
            break;
        default:
            return BT::inflt(pccnt);
        }
    }
};

#endif /* IDEAL_HH */
