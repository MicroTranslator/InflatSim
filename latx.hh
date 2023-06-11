#ifndef LATX_HH
#define LATX_HH 1

#include "bt.hh"

class Latx: public BT {
private:
    bool has_subreg_dest(cs_insn *insn) {
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_REG) {
                if(is_subreg(op->reg) && (op->access & CS_AC_WRITE))
                    return true;
            }
        }
        return false;
    }

    bool imm_inside_12bits(cs_insn *insn) {
        cs_x86 *x86 = &insn->detail->x86;
        for (int i = 0; i < x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_IMM) {
                // 全部符号扩展到64，再计算inflat
                int64_t imm = 0;
                switch (x86->encoding.imm_size)
                {
                    case 1:
                        imm = (int64_t)(int8_t)op->imm;
                        break;
                    case 2:
                        imm = (int64_t)(int16_t)op->imm;
                        break;
                    case 4:
                        imm = (int64_t)(int32_t)op->imm;
                        break;
                    case 8:
                        imm = op->imm;
                        break;
                    default:
                        break;
                }
                int bcsz = get_bcsz((int64_t)imm);
                return bcsz <= 12;
            }
        }
        return false;
    }

    int imm_inflt(cs_insn *insn, uint64_t imm) override {
        int bcsz = get_bcsz(imm);

        int tmp_32, tmp_52, tmp_64;
        tmp_32 = tmp_52 = tmp_64 = 0;

        tmp_32 = 1 + !all_zero(imm, 12);

        if(all_one(imm, 32)) tmp_52 = 2;
        else if(all_zero(imm, 32)) tmp_52 = 1;
        else tmp_52 = 1 + tmp_32;

        if(all_one(imm, 52)) tmp_64 = 2;
        else if(all_zero(imm, 52)) tmp_64 = 1;
        else tmp_64 = tmp_52 + 1;

        if(bcsz <= 12) return 0;
        else if(bcsz <= 32 || has_subreg_dest(insn)) return tmp_32;
        else if(bcsz <= 52) return tmp_52;
        else return tmp_64;
    }

    int disp_inflt(cs_insn *insn, uint64_t disp) override {
        int inflt = imm_inflt(insn, disp);
        // if(inflt) inflt ++ ; 
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM && insn->id != X86_INS_LEA) {
                if(op->mem.base && inflt) inflt ++ ; //考虑disp多于12bit的情况，如果base也存在，那会多搞出来一条add
            }
        }
        return inflt;
    }

    bool is_subreg(x86_reg r) override {
        switch (subreg_type(r)) {
            case SUBREG_LOW: case SUBREG_HIGH: case SUBREG_16BIT: case SUBREG_32BIT:
                return true;
            default:
                return false;
        }
    }

    bool all_reg_op(cs_insn *insn) {
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type != X86_OP_REG) {
                return false;
            }
        }
        return true;
    }

    // in latx, cmp_jcc has two instructions less than add_jcc
    // (jmp本身前面不需要x86setj指令，且cmp指令可以消除)
    int64_t cmp_jmp_fusion_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if (head->id==X86_INS_CMP && isJccOpt(tail->id))
            {
                // if(all_reg_op(head)) opt -= count; //暂时认为只有两个操作数都为reg类型才会消除
                opt -= 2 * count;
                cs_x86 *x86 = &head->detail->x86;
            }
        }
        // only count cmp+jcc fusion, which eliminate one instruction
        // 这个/2不会影响insts_inflt_breakdown_2017.pdf只会影响insts_inflt_breakdown_2017_opt.pdf
        excess_by_isa_feat[MY_FEAT_CMPJMP_FUSION_OPT] += opt/2;
        return opt;
    }


    //in latx, logic_jcc pair needs additonal flags calculate
    int64_t logic_jmp_pessi_sum_ex(TBCount *tbcnt) {
        int64_t pessi = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if (head->id != X86_INS_CMP && head->id != X86_INS_TEST && isJcc(tail->id)) {
                cs_x86 *x86 = &head->detail->x86;
                for (int i=0; i<x86->op_count; i++) {
                    cs_x86_op *op = &x86->operands[i];
                    if (op->type == X86_OP_IMM && imm_inside_12bits(head)) {
                        //当前运算指令中包含立即数操作时，由于latx计算符号位的限制，它要把该立即数搞到寄存器中来
                        //对于本来12bit以内，一条指令就能干完的运算类指令来讲，现在要额外多膨胀一条
                        //12bit以外的膨胀已经在计算立即数膨胀时包含了，不用管了
                        pessi += count;
                    }
                }
                pessi += count;
            }
        }

        excess_by_isa_feat[MY_FEAT_LOGIC_JCC_PESSI] += pessi;
        return pessi;
    }

    int64_t logic_cmov_pessi_sum_ex(TBCount *tbcnt) {
        int64_t pessi = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if (head->id != X86_INS_CMP && head->id != X86_INS_TEST  && isCmovcc(tail->id)) {
                cs_x86 *x86 = &head->detail->x86;
                for (int i=0; i<x86->op_count; i++) {
                    cs_x86_op *op = &x86->operands[i];
                    if (op->type == X86_OP_IMM && imm_inside_12bits(head)) {
                        //同上
                        pessi += count;
                    }
                }
                pessi += count;
            }
        }

        excess_by_isa_feat[MY_FEAT_LOGIC_CMOV_PESSI] += pessi;
        return pessi;
    }

    int inflt_extra_la_mov(PCCount *pccnt) {
        int inflt = inflt_extra_default(pccnt);
        uint64_t count = pccnt->count;
        if(imm_inside_12bits(pccnt->insn)) //对于12bit以内的立即数，我们也认为mov需要一条额外膨胀
        {
            inflt ++ ;
            excess_by_isa_feat[MY_FEAT_IMMLOAD] += count;
        }
        if(inflt) {
            inflt -- ; //对于有膨胀的mov指令，我们等价地将mov指令的base变为0
            excess_by_isa_feat[MY_FEAT_MOV_BASE_OPT] -= count;
        }
        return inflt;
    }

    int inflt_extra_la_cmp(PCCount *pccnt) {
        int inflt = inflt_extra_default(pccnt);
        uint64_t count = pccnt->count;

        if(imm_inside_12bits(pccnt->insn)) //对于12bit以内的立即数，我们也认为cmp需要一条额外膨胀
        {
            inflt ++ ;
            excess_by_isa_feat[MY_FEAT_IMMLOAD] += count;
        }

        // subreg
        int sub_inflt = 0;
        cs_x86_op* op0 = &pccnt->insn->detail->x86.operands[0];
        if (op0->type == X86_OP_REG) {
            if(is_subreg(op0->reg) && (subreg_type(op0->reg) != SUBREG_HIGH)) 
                sub_inflt ++;
        }
        excess_by_isa_feat[MY_FEAT_SUBREG] += sub_inflt * count;

        return inflt + sub_inflt;
    }

    int inflt_extra_test(PCCount *pccnt) {
        int inflt = inflt_extra_default(pccnt);
        uint64_t count = pccnt->count;

        if(imm_inside_12bits(pccnt->insn)) //对于12bit以内的立即数，我们也认为cmp需要一条额外膨胀
        {
            inflt ++ ;
            excess_by_isa_feat[MY_FEAT_IMMLOAD] += count;
        }

        return inflt;
    }

    int inflt_extra_la_movzx(PCCount *pccnt) {
        int mem = mem_inflt_ex(pccnt);  // read +1, write + 1
        int addr = addr_inflt_ex(pccnt);    // SIB: index || scale >1  +1. no disp!
        int immload = immload_inflt_ex(pccnt);  // disp + imm, 大于编码长度12， + 1

        int sub_inflt = 0;
        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {
                sub_inflt += subreg_inflt(op->mem.base);
                sub_inflt += subreg_inflt(op->mem.index);
            } else if (op->type == X86_OP_REG) {
                if((op->access & CS_AC_READ)) sub_inflt += 1;
                else if((op->access & CS_AC_WRITE) && subreg_type(op->reg) == SUBREG_16BIT) sub_inflt += 1;
            }
        }
        excess_by_isa_feat[MY_FEAT_SUBREG] += sub_inflt * count;
        pccnt->feats[MY_FEAT_SUBREG] += sub_inflt;

        int inflt = mem + addr + immload + sub_inflt;
        if(inflt) {
            inflt --;
            excess_by_isa_feat[MY_FEAT_MOV_BASE_OPT] -= count;
        }
        return inflt;
    }


    int addr_inflt_ex(PCCount *pccnt) override{
        int inflt = 0;
        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {
                inflt += addr_inflt(&op->mem);
            }
        }
        excess_by_isa_feat[MY_FEAT_ADDR] += inflt * count;
        pccnt->feats[MY_FEAT_ADDR] += inflt;
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
                case X86_INS_JNO: case X86_INS_JO:
                case X86_INS_JS: case X86_INS_JNS:
                case X86_INS_JNP: case X86_INS_JP:
                    opt += 8 * count;
                    break;
                default:
                case X86_INS_JA:  case X86_INS_JBE:
                case X86_INS_JE: case X86_INS_JNE:
                    opt -= 1 * count;
                    break;
                case X86_INS_JAE: case X86_INS_JB:
                case X86_INS_JG:  case X86_INS_JLE:
                case X86_INS_JGE: case X86_INS_JL:
                    opt -= 2 * count;
                    break;
                }
            }
        }

        excess_by_isa_feat[MY_FEAT_COMISJCC_OPT] += opt;
        return opt;
    }

    int64_t opt(TBCount *tbcnt) override {
        int64_t opt = 0;
        opt += BT::opt(tbcnt);
        opt += cmp_jmp_fusion_opt_sum_ex(tbcnt);
        opt += comis_jcc_opt_sum_ex(tbcnt);
        pushpop_esp_opt_sum_ex(tbcnt);    // 只统计，不是真正的优化

        return opt;
    }

    // movss/d (load from memory to the dst/src xmm) + add/sub/mulss/d: inflate 5 insts
    int64_t scalar_fp_pessi_sum_ex(TBCount *tbcnt) {
        int64_t pessi = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];

            if (
                head->id == X86_INS_MOVSS && 
                (tail->id == X86_INS_ADDSS || tail->id == X86_INS_SUBSS || tail->id == X86_INS_MULSS || tail->id == X86_INS_DIVSS)
            ) {
                int head_dst_xmm_idx = x86DstXMMidx(head);
                if (head_dst_xmm_idx < 0)
                    continue;
                if (head->detail->x86.operands[1].type != X86_OP_MEM)
                    continue;

                cs_x86 *tail_x86 = &tail->detail->x86;
                for (int i = 0; i < tail_x86->op_count; i++) {
                    cs_x86_op *tail_op = &tail_x86->operands[i];
                    if (tail_op->type == X86_OP_REG) {
                        int tail_op_xmm_idx = x86XMMidx(tail_op->reg);
                        if (tail_op_xmm_idx == head_dst_xmm_idx) {
                            pessi += 5 * count;
                            break;
        }}}}}

        excess_by_isa_feat[MY_FEAT_SCALAR_FP_PESSI] += pessi;
        return pessi;
    }

    int64_t pessi(TBCount *tbcnt) override {
        int64_t pessi = BT::pessi(tbcnt);
        pessi += logic_jmp_pessi_sum_ex(tbcnt);
        pessi += logic_cmov_pessi_sum_ex(tbcnt);
        pessi += scalar_fp_pessi_sum_ex(tbcnt);
        return pessi;
    }
public:
    Latx() {
        indirect_call_inflt = 9; //call reg = 16, base = 7, extra = 9
        indirect_jmp_inflt = 5;
    }

    BaseExtra inflt(PCCount *pccnt) override {
        cs_insn *insn = pccnt->insn;
        int base, extra;
        x86_insn id = x86_insn(insn->id);

        switch (id) {
            case X86_INS_CALL:
                return BaseExtra(7, inflt_extra_jmp(pccnt, indirect_call_inflt));
            case X86_INS_RET:
                return BaseExtra(3, 0);
            case X86_INS_JAE: case X86_INS_JA:  case X86_INS_JBE: case X86_INS_JB:
            case X86_INS_JE:  case X86_INS_JGE: case X86_INS_JG:  case X86_INS_JLE:
            case X86_INS_JL:  case X86_INS_JNE: case X86_INS_JNO: case X86_INS_JNP:
            case X86_INS_JNS: case X86_INS_JO:  case X86_INS_JP:  case X86_INS_JS:
                // TODO: jnz inflation is 1, how about others?
                return BaseExtra(2, 0);
            case X86_INS_ADD: case X86_INS_SUB:
            case X86_INS_AND: case X86_INS_OR: case X86_INS_XOR:
                return BaseExtra(1, inflt_extra_default(pccnt));
            case X86_INS_COMISS: case X86_INS_COMISD:
            case X86_INS_UCOMISS: case X86_INS_UCOMISD:
                return BaseExtra(1, inflt_extra_default(pccnt));
            case X86_INS_CMOVAE: case X86_INS_CMOVA:  case X86_INS_CMOVBE: case X86_INS_CMOVB:
            case X86_INS_CMOVE:  case X86_INS_CMOVGE: case X86_INS_CMOVG:  case X86_INS_CMOVLE:
            case X86_INS_CMOVL:  case X86_INS_CMOVNE: case X86_INS_CMOVNO: case X86_INS_CMOVNP:
            case X86_INS_CMOVNS: case X86_INS_CMOVO:  case X86_INS_CMOVP:  case X86_INS_CMOVS:
                return BaseExtra (4, inflt_extra_la_mov(pccnt));
            case X86_INS_CMP:
                return BaseExtra(1, inflt_extra_la_cmp(pccnt));
            case X86_INS_TEST:
                return BaseExtra(1, inflt_extra_test(pccnt));
            case X86_INS_MOV: case X86_INS_MOVSXD: case X86_INS_MOVABS:
            case X86_INS_MOVSS: case X86_INS_MOVSD: case X86_INS_MOVUPS: case X86_INS_MOVUPD: case X86_INS_MOVAPS: case X86_INS_MOVAPD:
                return BaseExtra(1, inflt_extra_la_mov(pccnt));
            case X86_INS_MOVZX:
                return BaseExtra(1, inflt_extra_la_movzx(pccnt));
            case X86_INS_MOVSX: 
                return BaseExtra(2, inflt_extra_la_mov(pccnt));
            case X86_INS_IDIV:
                return BaseExtra(12, inflt_extra_default(pccnt)); 
            case X86_INS_CVTDQ2PD :
                return BaseExtra(2, inflt_extra_default(pccnt));
            case X86_INS_CVTDQ2PS :
                return BaseExtra(1, inflt_extra_default(pccnt));
            case X86_INS_CVTPD2PS :
                return BaseExtra(3, inflt_extra_default(pccnt));
            case X86_INS_CVTPS2PD :
                return BaseExtra(5, inflt_extra_default(pccnt));
            case X86_INS_CVTSD2SS :
                return BaseExtra(2, inflt_extra_default(pccnt));
            case X86_INS_CVTSI2SD :
                return BaseExtra(3, inflt_extra_default(pccnt));
            case X86_INS_CVTSI2SS :
                return BaseExtra(3, inflt_extra_default(pccnt));
            case X86_INS_CVTSS2SD :
                return BaseExtra(2, inflt_extra_default(pccnt));
            case X86_INS_CVTTPD2DQ:
                return BaseExtra(16, inflt_extra_default(pccnt));
            case X86_INS_CVTTPS2DQ:
                return BaseExtra(29, inflt_extra_default(pccnt));
            case X86_INS_CVTTSD2SI:
                return BaseExtra(8, inflt_extra_default(pccnt));
            case X86_INS_CVTTSS2SI:
                return BaseExtra(8, inflt_extra_default(pccnt));
            case X86_INS_LAHF:
                return BaseExtra(4, inflt_extra_default(pccnt));
            default:
                return BT::inflt(pccnt);
        }

    }
};

#endif /* LATX_HH */
