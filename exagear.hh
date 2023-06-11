#ifndef EXAGEAR_HH
#define EXAGEAR_HH 1

#include "bt.hh"

class Exagear: public BT {
private:
    int addr_inflt(const x86_op_mem *mem) override {
        int inflt = 0;
        if (mem->scale>1)
            inflt++;
        if (mem->index && mem->disp)
            inflt++;

        // arm 有ldr指令，对于base + index (* 字长) 可以不膨胀
        if (mem->scale==8 && mem->index && mem->base)
            inflt--;

        return inflt;
    }

    int imm_inflt(cs_insn *insn, uint64_t imm) override {
        int inflt = 0;
        int bcsz = get_bcsz(imm);
        if (((int64_t)imm) < 0)
            bcsz--;
        if (insn->detail->x86.encoding.imm_size<8 && 12<bcsz && bcsz<=16)
            inflt++;
        inflt += BT::imm_inflt(insn, imm);

        if (is_bitmask_imm(imm))
            inflt = inflt<1 ? inflt:1;

        return inflt;
    }
    /* int disp_inflt(cs_insn *insn, uint64_t imm) override { */
    /*     int inflt = 0; */
    /*     int bcsz = get_bcsz(insn->address, imm); */
    /*     if (9<bcsz && bcsz<=12) */
    /*         inflt++; */
    /*     inflt += BT::disp_inflt(insn, imm); */
    /*     return inflt; */
    /* } */

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

    // in exagear, cmp_jcc has one instruction less than add_jcc
    int64_t cmp_jmp_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if (head->id==X86_INS_CMP && isJcc(tail->id))
                opt -= inflt_extra_jcc(tail) * count;
        }

        excess_by_isa_feat[MY_FEAT_EXAGEAR_CMPJMP_OPT] += opt;
        return opt;
    }
    int64_t comis_jcc_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if (isComis(head->id) && isJcc(tail->id)) {
                switch (tail->id) {
                default:
                case X86_INS_JA:  case X86_INS_JBE:
                case X86_INS_JG:  case X86_INS_JLE:
                    opt -= 1 * count;
                    break;
                case X86_INS_JE: case X86_INS_JNE:
                case X86_INS_JS: case X86_INS_JNS:
                    opt -= 2 * count;
                    break;
                case X86_INS_JGE: case X86_INS_JL:
                case X86_INS_JNO: case X86_INS_JO:
                    opt -= 3 * count;
                    break;
                case X86_INS_JAE: case X86_INS_JB:
                    opt -= 4 * count;
                    break;
                case X86_INS_JNP: case X86_INS_JP:
                    opt -= 8 * count;
                    break;
                }
            }
        }

        excess_by_isa_feat[MY_FEAT_COMISJCC_OPT] += opt;
        return opt;
    }
    int64_t cmp_cmov_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if (head->id==X86_INS_CMP && isCmovcc(tail->id))
                opt -= inflt_cmovcc(tail) * count;
        }

        excess_by_isa_feat[MY_FEAT_CMPCMOV_OPT] += opt;
        return opt;
    }
    int64_t test_jcc_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if (head->id==X86_INS_TEST && isJcc(tail->id)) {
                switch (tail->id) {
                default:
                case X86_INS_JE: case X86_INS_JNE:
                    opt -= 1 * count;
                    break;
                case X86_INS_JNP: case X86_INS_JP:
                case X86_INS_JG:  case X86_INS_JLE:
                case X86_INS_JS: case X86_INS_JNS:
                    opt -= 2 * count;
                    break;
                case X86_INS_JA:  case X86_INS_JBE:
                case X86_INS_JGE: case X86_INS_JL:
                    opt -= 3 * count;
                    break;
                case X86_INS_JNO: case X86_INS_JO:
                case X86_INS_JAE: case X86_INS_JB:
                    opt += 70 * count;
                    break;
                }
            }
        }

        excess_by_isa_feat[MY_FEAT_TESTJCC_OPT] += opt;
        return opt;
    }

    // if  head_addr + offset == tail_addr, offset unit: byte
    bool offset_match(cs_insn *head, cs_insn *tail, int64_t offset) {
        x86_op_mem *head_addr=NULL, *tail_addr=NULL;

        {cs_x86 *hx86 = &head->detail->x86;
        for (int opi=0; opi<hx86->op_count; opi++) {
            cs_x86_op *op = &hx86->operands[opi];
            if (op->type == X86_OP_MEM) {
                head_addr = &op->mem;
                break;
            }
        }
        if (!head_addr) return false;}

        {cs_x86 *tx86 = &tail->detail->x86;
        for (int opi=0; opi<tx86->op_count; opi++) {
            cs_x86_op *op = &tx86->operands[opi];
            if (op->type == X86_OP_MEM) {
                tail_addr = &op->mem;
                break;
            }
        }
        if (!tail_addr) return false;}

        if (head_addr->scale == tail_addr->scale &&
            head_addr->index == tail_addr->index &&
            head_addr->base  == tail_addr->base &&
            (head_addr->disp+offset) == tail_addr->disp)
            return true;
        else
            return false;
    }
    // in exagear movups and movupd, consecutive memory access will be merged as ldp/stp
    int64_t movupsd_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];

            if (head->id == X86_INS_MOVUPS && tail->id == X86_INS_MOVUPS ||
                head->id == X86_INS_MOVUPD && tail->id == X86_INS_MOVUPD
               ) {
                if (offset_match(head, tail, 0x10)) {
                    opt -= count;
                    insni++;
                }
            }
        }

        excess_by_isa_feat[MY_FEAT_VEC_LDST_PAIR_OPT] += opt;
        return opt;
    }


    int64_t opt(TBCount *tbcnt) override {
        int64_t opt = 0;
        opt += BT::opt(tbcnt);
        opt += cmp_jmp_opt_sum_ex(tbcnt);
        opt += comis_jcc_opt_sum_ex(tbcnt);
        opt += cmp_cmov_opt_sum_ex(tbcnt);
        opt += test_jcc_opt_sum_ex(tbcnt);
        opt += addr_opt_sum_ex(tbcnt);
        opt += movupsd_opt_sum_ex(tbcnt);
        opt += pushpop_pair_opt_sum_ex(tbcnt);
        return opt;
    }

    int inflt_extra_movext(PCCount *pccnt) {
        int inflt = inflt_extra_mov(pccnt);

        // get src and dst operand
        cs_x86_op *src, *dst;
        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->access & CS_AC_READ)
                src = op;
            else if (op->access & CS_AC_WRITE)
                dst = op;
        }

        // sign/zero: x->16
        if (dst->size == 2)
            inflt++;
        // sign/zero: h->32
        else if (src->type==X86_OP_REG && subreg_type(src->reg)==SUBREG_HIGH && dst->size==4)
            inflt++;

        return inflt;
    }

    int inflt_extra_jcc(PCCount *pccnt) {
        return inflt_extra_jcc(pccnt->insn);
    }
    int inflt_extra_jcc(cs_insn *insn) {
        switch (insn->id) {
        case X86_INS_JNP: case X86_INS_JP:
            return 6;
        case X86_INS_JAE: case X86_INS_JB:
        case X86_INS_JNO: case X86_INS_JO:
        case X86_INS_JA:  case X86_INS_JBE:
        case X86_INS_JGE: case X86_INS_JL:
        case X86_INS_JG:  case X86_INS_JLE:
            return 3;
        case X86_INS_JE: case X86_INS_JNE:
        case X86_INS_JS: case X86_INS_JNS:
        default:
            return 2;
        }
    }
    int inflt_extra_cmovcc(PCCount *pccnt) {
        int inflt = inflt_extra_default(pccnt);
        inflt += inflt_cmovcc(pccnt->insn);
        return inflt;
    }
    int inflt_cmovcc(cs_insn *insn) {
        switch (insn->id) {
        case X86_INS_CMOVNP: case X86_INS_CMOVP:
            return 6;
        case X86_INS_CMOVAE: case X86_INS_CMOVB:
        case X86_INS_CMOVNO: case X86_INS_CMOVO:
        case X86_INS_CMOVA:  case X86_INS_CMOVBE:
        case X86_INS_CMOVGE: case X86_INS_CMOVL:
        case X86_INS_CMOVG:  case X86_INS_CMOVLE:
            return 3;
        case X86_INS_CMOVE: case X86_INS_CMOVNE:
        case X86_INS_CMOVS: case X86_INS_CMOVNS:
        default:
            return 2;
        }
    }

public:
    Exagear() {
        indirect_jmp_inflt = 12;
        indirect_call_inflt = 8;
        bitmask_imms_init();
    }

    BaseExtra inflt(PCCount *pccnt) override {
        cs_insn *insn = pccnt->insn;
        int base, extra;
        x86_insn id = x86_insn(insn->id);

        // calculate base
        switch (id) {
        case X86_INS_CALL:
            return BaseExtra(6, inflt_extra_jmp(pccnt, indirect_call_inflt));
        case X86_INS_RET:
            return BaseExtra(10, 0);
        case X86_INS_MOVSX: case X86_INS_MOVSXD: case X86_INS_MOVZX:
            return BaseExtra(1, inflt_extra_movext(pccnt));
        case X86_INS_JAE: case X86_INS_JA:  case X86_INS_JBE: case X86_INS_JB:
        case X86_INS_JE:  case X86_INS_JGE: case X86_INS_JG:  case X86_INS_JLE:
        case X86_INS_JL:  case X86_INS_JNE: case X86_INS_JNO: case X86_INS_JNP:
        case X86_INS_JNS: case X86_INS_JO:  case X86_INS_JP:  case X86_INS_JS:
            return BaseExtra(1, inflt_extra_jcc(pccnt));
        case X86_INS_COMISS: case X86_INS_COMISD:
        case X86_INS_UCOMISS: case X86_INS_UCOMISD:
            return BaseExtra(7, inflt_extra_default(pccnt));
        case X86_INS_CMOVAE: case X86_INS_CMOVA:  case X86_INS_CMOVBE: case X86_INS_CMOVB:
        case X86_INS_CMOVE:  case X86_INS_CMOVGE: case X86_INS_CMOVG:  case X86_INS_CMOVLE:
        case X86_INS_CMOVL:  case X86_INS_CMOVNE: case X86_INS_CMOVNO: case X86_INS_CMOVNP:
        case X86_INS_CMOVNS: case X86_INS_CMOVO:  case X86_INS_CMOVP:  case X86_INS_CMOVS:
            return BaseExtra (1, inflt_extra_cmovcc(pccnt));
        case X86_INS_MULPD: case X86_INS_MULPS:
        case X86_INS_MULSD: case X86_INS_MULSS:
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_DIV:
            return BaseExtra(9, inflt_extra_default(pccnt)); 
        case X86_INS_IDIV:
            return BaseExtra(14, inflt_extra_default(pccnt)); 
        case X86_INS_DIVPD: case X86_INS_DIVPS:
        case X86_INS_DIVSD: case X86_INS_DIVSS:
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CVTDQ2PD :
            return BaseExtra(2, inflt_extra_default(pccnt));
        case X86_INS_CVTDQ2PS :
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CVTPD2PS :
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CVTPS2PD :
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CVTSD2SS :
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CVTSI2SD :
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CVTSI2SS :
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CVTSS2SD :
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CVTTPD2DQ:
            return BaseExtra(10, inflt_extra_default(pccnt));
        case X86_INS_CVTTPS2DQ:
            return BaseExtra(7, inflt_extra_default(pccnt));
        case X86_INS_CVTTSD2SI:
            return BaseExtra(4, inflt_extra_default(pccnt));
        case X86_INS_CVTTSS2SI:
            return BaseExtra(4, inflt_extra_default(pccnt));
        case X86_INS_LAHF:
            return BaseExtra(101, inflt_extra_default(pccnt));
        default:
            return BT::inflt(pccnt);
        }

        return BaseExtra(base, extra);
    }
};

#endif /* EXAGEAR_HH */
