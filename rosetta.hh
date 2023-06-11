#ifndef ROSETTA_HH
#define ROSETTA_HH 1

#include "bt.hh"

class Rosetta: public BT {
private:
    int imm_inflt(cs_insn *insn, uint64_t imm) override {
        int inflt = BT::imm_inflt(insn, imm);

        if (is_bitmask_imm(imm))
            inflt = inflt<1 ? inflt:1;

        return inflt;
    }

    int addr_inflt(const x86_op_mem *mem) override{
        // SIBD额外膨胀为1
        if (mem->scale>1 && mem->index && mem->base && mem->disp)
            return 1;
        int inflt = 0;
        if (mem->scale>1)
            inflt++;
        if (mem->index && mem->disp)
            inflt++;

        // arm 有ldr指令，对于base + index (* 字长) 可以不膨胀
        if (mem->scale==8 && mem->index && mem->base)
            inflt--;

        // 特例
        if (mem->scale==1 && mem->index && !mem->base && mem->disp)
            inflt++;

        return inflt;
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

        // sign/zero: l->16
        if (src->type==X86_OP_REG && subreg_type(src->reg)==SUBREG_LOW && dst->size==2)
            inflt++;

        return inflt;
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
                case X86_INS_JA:  case X86_INS_JBE:
                    opt += 2 * count;
                    break;
                default:
                case X86_INS_JE: case X86_INS_JNE:
                case X86_INS_JG:  case X86_INS_JLE:
                case X86_INS_JAE: case X86_INS_JB:
                    opt -= 1 * count;
                    break;
                case X86_INS_JNO: case X86_INS_JO:
                case X86_INS_JGE: case X86_INS_JL:
                case X86_INS_JS: case X86_INS_JNS:
                    opt -= 2 * count;
                    break;
                case X86_INS_JNP: case X86_INS_JP:
                    opt -= 4 * count;
                    break;
                }
            }
        }

        excess_by_isa_feat[MY_FEAT_COMISJCC_OPT] += opt;
        return opt;
    }

    int inflt_extra_cmovcc(PCCount *pccnt) {
        int inflt = inflt_extra_default(pccnt);
        inflt += inflt_cmovcc(pccnt->insn);
        return inflt;
    }
    int inflt_cmovcc(cs_insn *insn) {
        switch (insn->id) {
        case X86_INS_CMOVNP: case X86_INS_CMOVP:
            return 9;
        case X86_INS_CMOVA:  case X86_INS_CMOVBE:
        case X86_INS_CMOVAE: case X86_INS_CMOVB:
            return 1;
        case X86_INS_CMOVNO: case X86_INS_CMOVO:
        case X86_INS_CMOVGE: case X86_INS_CMOVL:
        case X86_INS_CMOVG:  case X86_INS_CMOVLE:
        case X86_INS_CMOVE: case X86_INS_CMOVNE:
        case X86_INS_CMOVS: case X86_INS_CMOVNS:
        default:
            return 0;
        }
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
                if (inflt_cmovcc(tail))
                    opt -= 1 * count;
        }

        excess_by_isa_feat[MY_FEAT_CMPCMOV_OPT] += opt;
        return opt;
    }

    int64_t scalar_fp_pessi_sum_ex(TBCount *tbcnt) {
        int64_t pessi = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

#define SF_PESSI_INVALID 0
#define SF_PESSI_SINGLE 1
#define SF_PESSI_DOUBLE 2
        uint8_t xmm_status[16] = {SF_PESSI_INVALID};
        for (int insni=0; insni<n_insns; insni++) {
            cs_insn *insn = insns[insni];
            if (insn->id == X86_INS_MOVSS || insn->id == X86_INS_MOVSD) {
                int dst_xmm_idx = x86DstXMMidx(insn);
                if (dst_xmm_idx < 0) // fuck capstone, fuck x86: mov string double, mov scalar double have the same name movsd
                    continue;

                cs_x86_op *src_op = &insn->detail->x86.operands[1];
                if (src_op->type == X86_OP_REG) {
                    int src_xmm_idx = x86XMMidx(src_op->reg);
                    xmm_status[dst_xmm_idx] = xmm_status[src_xmm_idx];
                } else if (src_op->type == X86_OP_MEM) {
                    if (insn->id == X86_INS_MOVSS)
                        xmm_status[dst_xmm_idx] = SF_PESSI_SINGLE;
                    else
                        xmm_status[dst_xmm_idx] = SF_PESSI_DOUBLE;
                }
            } else if (insn->id == X86_INS_ADDSS || insn->id == X86_INS_SUBSS || insn->id == X86_INS_MULSS || insn->id == X86_INS_DIVSS) {
                int dst_xmm_idx = x86DstXMMidx(insn);
                if (dst_xmm_idx < 0)
                    continue;

                if (xmm_status[dst_xmm_idx] != SF_PESSI_SINGLE)
                    pessi += 1 * count;
            } else if (insn->id == X86_INS_ADDSD || insn->id == X86_INS_SUBSD || insn->id == X86_INS_MULSD || insn->id == X86_INS_DIVSD) {
                int dst_xmm_idx = x86DstXMMidx(insn);
                if (dst_xmm_idx < 0)
                    continue;

                if (xmm_status[dst_xmm_idx] != SF_PESSI_DOUBLE)
                    pessi += 1 * count;
            }
        }
#undef SF_PESSI_INVALID
#undef SF_PESSI_SINGLE
#undef SF_PESSI_DOUBLE

        excess_by_isa_feat[MY_FEAT_SCALAR_FP_PESSI] += pessi;
        return pessi;
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
                case X86_INS_JAE: case X86_INS_JB:
                case X86_INS_JA:  case X86_INS_JBE:
                    opt += 1 * count;
                    break;
                default:
                    break;
                }
            }
        }

        excess_by_isa_feat[MY_FEAT_TESTJCC_PESSI] += opt;
        return opt;
    }

public:
    Rosetta() {
        indirect_jmp_inflt = 40;
        indirect_call_inflt = 8;
        // 使用nanobench/indirect_jump 随机访存测试测出斜率在40左右
        // call reg=16, base=10, extra=6
        bitmask_imms_init();
    }

    BaseExtra inflt(PCCount *pccnt) override {
        cs_insn *insn = pccnt->insn;
        int base, extra;
        x86_insn id = x86_insn(insn->id);

        // calculate base
        switch (id) {
        case X86_INS_POP:
            return BaseExtra(2, inflt_extra_default(pccnt));
        case X86_INS_MOVSX: case X86_INS_MOVSXD: case X86_INS_MOVZX:
            return BaseExtra(1, inflt_extra_movext(pccnt));
        case X86_INS_JAE: case X86_INS_JA:  case X86_INS_JBE: case X86_INS_JB:
        case X86_INS_JE:  case X86_INS_JGE: case X86_INS_JG:  case X86_INS_JLE:
        case X86_INS_JL:  case X86_INS_JNE: case X86_INS_JNO:
        case X86_INS_JNS: case X86_INS_JO:  case X86_INS_JS:
            return BaseExtra(1, 0);
        case X86_INS_JP: case X86_INS_JNP:
            return BaseExtra(6, 0);
        case X86_INS_CMOVNP: case X86_INS_CMOVP:
        case X86_INS_CMOVA:  case X86_INS_CMOVBE:
        case X86_INS_CMOVAE: case X86_INS_CMOVB:
        case X86_INS_CMOVNO: case X86_INS_CMOVO:
        case X86_INS_CMOVGE: case X86_INS_CMOVL:
        case X86_INS_CMOVG:  case X86_INS_CMOVLE:
        case X86_INS_CMOVE: case X86_INS_CMOVNE:
        case X86_INS_CMOVS: case X86_INS_CMOVNS:
            return BaseExtra(1, inflt_extra_cmovcc(pccnt));
        case X86_INS_COMISS: case X86_INS_COMISD:
        case X86_INS_UCOMISS: case X86_INS_UCOMISD:
            return BaseExtra(4, inflt_extra_default(pccnt));
        case X86_INS_MULSD: case X86_INS_MULSS:
        case X86_INS_DIVSD: case X86_INS_DIVSS:
        case X86_INS_ADDSS: case X86_INS_ADDSD:
        case X86_INS_SUBSS: case X86_INS_SUBSD:
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_MUL: case X86_INS_MULX:
        case X86_INS_MULPD: case X86_INS_MULPS:
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_DIV:
            return BaseExtra(7, inflt_extra_default(pccnt));
        case X86_INS_IDIV:
            return BaseExtra(10, inflt_extra_default(pccnt)); 
        case X86_INS_DIVPD: case X86_INS_DIVPS:
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
            return BaseExtra(2, inflt_extra_default(pccnt));
        case X86_INS_CVTSI2SD :
            return BaseExtra(2, inflt_extra_default(pccnt));
        case X86_INS_CVTSI2SS :
            return BaseExtra(2, inflt_extra_default(pccnt));
        case X86_INS_CVTSS2SD :
            return BaseExtra(2, inflt_extra_default(pccnt));
        case X86_INS_CVTTPD2DQ:
            return BaseExtra(15, inflt_extra_default(pccnt));
        case X86_INS_CVTTPS2DQ:
            return BaseExtra(8, inflt_extra_default(pccnt));
        case X86_INS_CVTTSD2SI:
            return BaseExtra(9, inflt_extra_default(pccnt));
        case X86_INS_CVTTSS2SI:
            return BaseExtra(9, inflt_extra_default(pccnt));
        case X86_INS_LAHF:
            return BaseExtra(15, inflt_extra_default(pccnt));
        default:
            return BT::inflt(pccnt);
        }

        return BaseExtra(base, extra);
    }

    int64_t add_jcc_cf_ex(TBCount *tbcnt) {
        int64_t pessi = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if ((
                head->id == X86_INS_ADD ||
                head->id == X86_INS_ADC ||
                head->id == X86_INS_INC
               ) && (
                tail->id == X86_INS_JAE || // !CF
                tail->id == X86_INS_JA  || // !(CF!ZF)
                tail->id == X86_INS_JBE || // CF|ZF
                tail->id == X86_INS_JB     // CF
               )) {
                pessi += count;
            }
        }

        excess_by_isa_feat[MY_FEAT_ROSETTA_ADD_JCC_CF_PESSI] += pessi;
        return pessi;
    }
    int64_t pessi(TBCount *tbcnt) override {
        int64_t pessi = BT::pessi(tbcnt);
        pessi += add_jcc_cf_ex(tbcnt);
        pessi += scalar_fp_pessi_sum_ex(tbcnt);
        return pessi;
    }

    int64_t opt(TBCount *tbcnt) override {
        int64_t opt = 0;
        opt += BT::opt(tbcnt);
        opt += pushpop_pair_opt_sum_ex(tbcnt);
        opt += comis_jcc_opt_sum_ex(tbcnt);
        opt += cmp_cmov_opt_sum_ex(tbcnt);
        opt += test_jcc_opt_sum_ex(tbcnt);
        return opt;
    }
};

#endif /* ROSETTA_HH */
