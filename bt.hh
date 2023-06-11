#ifndef BT_HH
#define BT_HH 1

// TODO: sse_test: exagear continous memory access to ldp
#include <capstone/capstone.h>
#include <utility>
#include <map>
#include <list>

#include "mygrpinfo.h"
#include "bitmask_imms.hh"

// todo rosetta, exagear, lahf , load eflags?
// todo h->h = 4, 16->16=2
// todo rosetta call reg 可能更低

typedef std::pair<int, int> BaseExtra;
enum MyBTFeatId {
    MY_FEAT_INVALID = 0,
    MY_FEAT_BEGINING,

    MY_FEAT_MEM = MY_FEAT_BEGINING,
    MY_FEAT_ADDR,
    MY_FEAT_IMMLOAD,
    MY_FEAT_IMMLOAD_OPT,
    MY_FEAT_INDIR_CTRLTRSF,
    MY_FEAT_SUBREG,
    MY_FEAT_CMPJMP_FUSION_OPT,
    MY_FEAT_EXAGEAR_CMPJMP_OPT,
    MY_FEAT_COMISJCC_OPT,
    MY_FEAT_CMPCMOV_OPT,
    MY_FEAT_TESTJCC_OPT,
    MY_FEAT_TESTJCC_PESSI,
    MY_FEAT_ADDR_PRECALC_OPT,
    MY_FEAT_LOGIC_JCC_PESSI,
    MY_FEAT_LOGIC_CMOV_PESSI,
    MY_FEAT_ROSETTA_ADD_JCC_CF_PESSI,
    MY_FEAT_MOV_BASE_OPT,
    MY_FEAT_VEC_LDST_PAIR_OPT,
    MY_FEAT_PUSHPOP_PAIR_OPT,
    MY_FEAT_PUSHPOP_ELISION_OPT,
    MY_FEAT_SCALAR_FP_PESSI,
    MY_FEAT_FUSION_OPT,
    MY_FEAT_ENDING,
};

typedef struct {
    uint64_t count;     // execute count
    uint64_t vaddr;     // virtual address
    size_t n_insns;     // number of instructions
    cs_insn **cs_insns; // capstone instruction instances
} TBCount;
typedef struct {
    uint64_t count;   // execute count
    uint64_t vaddr;   // virtual address
    cs_insn *insn; // capstone instruction instance
    uint64_t inflt;   // inflation
    int feats[MY_FEAT_ENDING];
} PCCount;

const char *MyBTFeatStr[] = {
    [MY_FEAT_INVALID] = "invalid",
    [MY_FEAT_MEM] = "mem",
    [MY_FEAT_ADDR] = "addr",
    [MY_FEAT_IMMLOAD] = "immload",
    [MY_FEAT_IMMLOAD_OPT] = "immload_opt",
    [MY_FEAT_INDIR_CTRLTRSF] = "indir_ctrltrsf",
    [MY_FEAT_SUBREG] = "subreg",
    [MY_FEAT_CMPJMP_FUSION_OPT] = "cmpjmp_fusion_opt",
    [MY_FEAT_EXAGEAR_CMPJMP_OPT] = "exagear_cmpjmp_opt",
    [MY_FEAT_COMISJCC_OPT] = "comisjcc_opt",
    [MY_FEAT_CMPCMOV_OPT] = "cmpcmov_opt",
    [MY_FEAT_TESTJCC_OPT] = "testjcc_opt",
    [MY_FEAT_TESTJCC_PESSI] = "testjcc_pessi",
    [MY_FEAT_ADDR_PRECALC_OPT] = "addr_precalc_opt",
    [MY_FEAT_LOGIC_JCC_PESSI] = "logic_jmp_pessi",
    [MY_FEAT_LOGIC_CMOV_PESSI] = "logic_cmov_pessi",
    [MY_FEAT_ROSETTA_ADD_JCC_CF_PESSI] = "rosetta_add_jcc_cf_pessi",
    [MY_FEAT_MOV_BASE_OPT] = "mov_base_opt",
    [MY_FEAT_VEC_LDST_PAIR_OPT] = "vec_ldst_pair_opt",
    [MY_FEAT_PUSHPOP_PAIR_OPT] = "pushpop_pair_opt",
    [MY_FEAT_PUSHPOP_ELISION_OPT]  = "pushpop_elision_opt",
    [MY_FEAT_SCALAR_FP_PESSI] = "scalar_fp_pessi",
    [MY_FEAT_FUSION_OPT] = "fusion_opt",
};

int64_t excess_by_isa_feat[MY_FEAT_ENDING];

// bit compression: compression result granularity: 1~64
static int get_bcsz(int64_t operand) {
    if (!operand)
        return 1; // clz result is undefined if input is 0
    // __builtin_clzl 统计从最高位的连续0的个数
    int z = __builtin_clzl(operand);   // leading zeros
    int o = __builtin_clzl(~operand);  // leading ones
    // fprintf(stderr, "0x%lx z%d o%d res%d\n", operand, z, o, 65 - (z>o?z:o));
    return 65 - (z>o?z:o); // why 65? Because signess need one bit
}

enum SubRegType {
    SUBREG_INVALID = 0,

    SUBREG_8BIT,
    SUBREG_LOW = SUBREG_8BIT,
    SUBREG_HIGH,
    SUBREG_16BIT,
    SUBREG_32BIT,
    SUBREG_64BIT,

    SUBREG_ENDING,
};
static SubRegType subreg_type(x86_reg r) {
    switch(r) {
    case X86_REG_AL: case X86_REG_BL: case X86_REG_CL: case X86_REG_DL:
    case X86_REG_BPL: case X86_REG_SIL: case X86_REG_DIL: case X86_REG_SPL:
    case X86_REG_R8B: case X86_REG_R9B: case X86_REG_R10B: case X86_REG_R11B:
    case X86_REG_R12B: case X86_REG_R13B: case X86_REG_R14B: case X86_REG_R15B:
        return SUBREG_LOW;
    case X86_REG_AH: case X86_REG_BH: case X86_REG_CH: case X86_REG_DH:
        return SUBREG_HIGH;
    case X86_REG_AX: case X86_REG_BX: case X86_REG_CX: case X86_REG_DX:
    case X86_REG_BP: case X86_REG_SI: case X86_REG_DI: case X86_REG_SP:
    case X86_REG_R8W: case X86_REG_R9W: case X86_REG_R10W: case X86_REG_R11W:
    case X86_REG_R12W: case X86_REG_R13W: case X86_REG_R14W: case X86_REG_R15W:
        return SUBREG_16BIT;
    case X86_REG_EAX: case X86_REG_EBX: case X86_REG_ECX: case X86_REG_EDX:
    case X86_REG_EBP: case X86_REG_ESI: case X86_REG_EDI: case X86_REG_ESP:
    case X86_REG_R8D: case X86_REG_R9D: case X86_REG_R10D: case X86_REG_R11D:
    case X86_REG_R12D: case X86_REG_R13D: case X86_REG_R14D: case X86_REG_R15D:
        return SUBREG_32BIT;
    case X86_REG_RAX: case X86_REG_RBX: case X86_REG_RCX: case X86_REG_RDX:
    case X86_REG_RBP: case X86_REG_RSI: case X86_REG_RDI: case X86_REG_RSP:
    case X86_REG_R8: case X86_REG_R9: case X86_REG_R10: case X86_REG_R11:
    case X86_REG_R12: case X86_REG_R13: case X86_REG_R14: case X86_REG_R15:
        return SUBREG_64BIT;
    default:
        return SUBREG_INVALID;
    }
}

class BT {
private:
protected:
    int indirect_jmp_inflt;
    int indirect_call_inflt;

    // Noted: function with prefix `inflt_extra` are used to calculate the extra in BaseExtra

    virtual int inflt_extra_default(PCCount *pccnt) {
        // 默认对于所有的计算类指令
        int mem = mem_inflt_ex(pccnt);  // read +1, write + 1
        int addr = addr_inflt_ex(pccnt);    // SIB: index || scale >1  +1. no disp!
        int immload = immload_inflt_ex(pccnt);  // disp + imm, 大于编码长度12， + 1
        int subreg = subreg_inflt_ex(pccnt);    // mem(base+index) + reg, low/high/16, +1
        return mem + addr + immload + subreg;
    }

    // TODO:
    virtual int inflt_extra_mov(PCCount *pccnt) {
        int inflt = inflt_extra_default(pccnt);
        uint64_t count = pccnt->count;
        /* if(imm_inside_12bits(pccnt->insn)) //对于12bit以内的立即数，我们也认为mov需要一条额外膨胀 */
        /* { */
        /*     inflt ++ ; */
        /*     excess_by_isa_feat[MY_FEAT_IMMLOAD] += count; */
        /* } */
        if(inflt) {
            inflt -- ; //对于有膨胀的mov指令，我们等价地将mov指令的base变为0
            excess_by_isa_feat[MY_FEAT_MOV_BASE_OPT] -= count;
        }
        return inflt;
    }

    virtual int inflt_extra_lea(PCCount *pccnt) {
        int addr = addr_inflt_ex(pccnt);
        int immload = immload_inflt_ex(pccnt);
        int subreg = subreg_inflt_ex(pccnt);

        return addr + immload + subreg;
    }

    // call, jmp 共享这个函数，只是indiect_inflt参数不同
    virtual int inflt_extra_jmp(PCCount *pccnt, int indirect_inflt) {
        int mem = mem_inflt_ex(pccnt);
        int addr = addr_inflt_ex(pccnt);
        int subreg = subreg_inflt_ex(pccnt);
        int immload = 0;
        int indirjmp = 0;

        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type != X86_OP_IMM) {
                indirjmp = indirect_inflt;
                break;
            }
        }

        if (indirjmp) {
            excess_by_isa_feat[MY_FEAT_INDIR_CTRLTRSF] += indirjmp * count;
            pccnt->feats[MY_FEAT_INDIR_CTRLTRSF] += indirjmp;
            immload = immload_inflt_ex(pccnt);
        } else {
            // Arm64 b and bl are 26+2 imm offset
            // Arm64 b.cond are 19+2 imm offset
            // Consider branch target is code cache, not x86 addr
            // I assume code cache is well arranged, no need immload for direct branch instructions
        }

        return mem + addr + subreg + immload + indirjmp;
    }

    virtual int inflt_extra_cmp(PCCount *pccnt) {
        int inflt = 0;

        cs_x86_op* op0 = &pccnt->insn->detail->x86.operands[0];
        if (op0->type == X86_OP_REG) {
            if(is_subreg(op0->reg))
                inflt++;
            inflt += subreg_inflt(op0->reg);
        }

        excess_by_isa_feat[MY_FEAT_SUBREG] += inflt * pccnt->count;
        pccnt->feats[MY_FEAT_SUBREG] += inflt;
        return inflt + inflt_extra_default(pccnt);
    }

    // Noted: function with suffix `_ex` means this function will count excess_by_isa_feat


    bool all_one(uint64_t val, int cnt) {
        uint64_t mask = ((uint64_t)1 << cnt) - 1;
        if((val & mask) == mask) return true;
        else return false;
    }

    bool all_zero(uint64_t val, int cnt) {
        uint64_t mask = ((uint64_t)1 << cnt) - 1;
        if((val & mask) == 0) return true;
        else return false;
    }
    virtual int imm_inflt(cs_insn *insn, uint64_t imm) {
        uint64_t masks[4] = {
            0xffffULL,
            0xffff0000ULL,
            0xffff00000000ULL,
            0xffff000000000000ULL,
        };
        int inflt = 0;

        int bcsz = get_bcsz(imm);
        if(bcsz <= 12) return 0;

        for (int i=0; i<4; i++) {
            if ((imm & masks[i])!=masks[i] && (imm & masks[i])) {
                inflt++;
            }
        }
        return inflt;

        /* int tmp_32, tmp_48, tmp_64; */
        /* tmp_32 = tmp_48 = tmp_64 = 0; */

        /* tmp_32 = 1 + !all_zero(imm, 16); */

        /* if(all_one(imm, 32)) tmp_48 = 2; */
        /* else if(all_zero(imm, 32)) tmp_48 = 1; */
        /* else tmp_48 = 1 + tmp_32; */

        /* if(all_one(imm, 48)) tmp_64 = 2; */
        /* else if(all_zero(imm, 48)) tmp_64 = 1; */
        /* else tmp_64 = tmp_48 + 1; */

        /* int bcsz = get_bcsz(insn->address, imm); */
        /* if(bcsz <= 12) return 0; */
        /* else if(bcsz <= 16) return 1; */
        /* // TODO subreg_dest */
        /* else if(bcsz <= 32) return tmp_32; */
        /* else if(bcsz <= 48) return tmp_48; */
        /* else return tmp_64; */
    }

    virtual int disp_inflt(cs_insn *insn, uint64_t disp) {
        int inflt = imm_inflt(insn, disp);
        // if(inflt) inflt ++ ; 
        /* cs_x86 *x86 = &insn->detail->x86; */
        /* for (int i=0; i<x86->op_count; i++) { */
        /*     cs_x86_op *op = &x86->operands[i]; */
        /*     if (op->type == X86_OP_MEM) { */
        /*         if(op->mem.base && inflt) inflt ++ ; //考虑disp多于12bit的情况，如果base也存在，那会多搞出来一条add */
        /*     } */
        /* } */
        return inflt;
    }
    virtual int immload_inflt_ex(PCCount *pccnt) {
        int inflt = 0;
        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {
                int64_t disp = 0;
                switch (x86->encoding.disp_size)
                {
                    case 1:
                        disp = (int64_t)(int8_t)op->mem.disp;
                        break;
                    case 2:
                        disp = (int64_t)(int32_t)op->mem.disp; //there maybe a problem in cpastone for movw kinds
                        break;
                    case 4:
                        disp = (int64_t)(int32_t)op->mem.disp;
                        break;
                    default:
                        break;
                }
                if (op->mem.base == X86_REG_RIP)
                    disp += insn->address;
                inflt += disp_inflt(insn, (int64_t)disp);
            } else if (op->type == X86_OP_IMM) {
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
                inflt += imm_inflt(insn,(int64_t)imm);
                pccnt->feats[MY_FEAT_IMMLOAD_OPT] = imm;
            }
        }
        excess_by_isa_feat[MY_FEAT_IMMLOAD] += inflt * count;
        pccnt->feats[MY_FEAT_IMMLOAD] += inflt;
        return inflt;
    };

    virtual int mem_inflt_ex(PCCount *pccnt) {
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
                    inflt++;
                if (op->access & CS_AC_WRITE)
                    inflt++;
            }
        }
        excess_by_isa_feat[MY_FEAT_MEM] += inflt * count;
        pccnt->feats[MY_FEAT_MEM] += inflt;
        return inflt;
    }

    virtual int addr_inflt(const x86_op_mem *mem) {
        return mem->index || mem->scale>1;
    }
    virtual int addr_inflt_ex(PCCount *pccnt) {
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

    virtual int subreg_inflt(x86_reg r) {
        SubRegType t = subreg_type(r);
        switch (t) {
            case SUBREG_HIGH:
                return 1;
            default:
                return 0;
        }
    }

    virtual bool is_subreg(x86_reg r) {
        switch (subreg_type(r)) {
            case SUBREG_LOW: case SUBREG_HIGH: case SUBREG_16BIT:
                return true;
            default:
                return false;
        }
    }
    virtual int subreg_inflt_ex(PCCount *pccnt) {
        int inflt = 0;
        cs_insn *insn = pccnt->insn;
        uint64_t count = pccnt->count;
        cs_x86 *x86 = &insn->detail->x86;
        for (int i=0; i<x86->op_count; i++) {
            cs_x86_op *op = &x86->operands[i];
            if (op->type == X86_OP_MEM) {
                inflt += subreg_inflt(op->mem.base);
                inflt += subreg_inflt(op->mem.index);
            } else if (op->type == X86_OP_REG) {
                if(is_subreg(op->reg) && (op->access & CS_AC_WRITE)) {
                    inflt += 1;
                    if(insn->id == X86_INS_MOV) continue;
                }
                inflt += subreg_inflt(op->reg);
            }
        }
        excess_by_isa_feat[MY_FEAT_SUBREG] += inflt * count;
        pccnt->feats[MY_FEAT_SUBREG] += inflt;
        return inflt;
    }

    // Noted: all opt function return negative number

    // rosetta and exagear doesn't have this opt?
    virtual int64_t immload_opt_sum_ex(TBCount *tbcnt) {
        typedef struct ImmCount {
            int count;
            int inflt;
        } ImmCount;
        typedef std::map<uint64_t, ImmCount> ImmStat;
        ImmStat immstat;

        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;
        for (int insni=0; insni<n_insns; insni++) {
            cs_insn *insn = insns[insni];
            cs_x86 *x86 = &insn->detail->x86;
            for (int i=0; i<x86->op_count; i++) {
                cs_x86_op *op = &x86->operands[i];
                if (op->type == X86_OP_MEM) {
                    ImmStat::iterator iter = immstat.find(op->mem.disp);
                    if (iter == immstat.end()) { // not found
                        immstat[op->mem.disp] = {
                            .count = 0,
                            .inflt = disp_inflt(insn, op->mem.disp)
                        };
                    } else { // found
                        immstat[op->mem.disp].count++;
                    }
                } else if (op->type == X86_OP_IMM) {
                    ImmStat::iterator iter = immstat.find(op->imm);
                    if (iter == immstat.end()) { // not found
                        immstat[op->imm] = {
                            .count = 0,
                            .inflt = imm_inflt(insn, op->imm)
                        };
                    } else { // found
                        immstat[op->imm].count++;
                    }
                }
            }
        }

        for (const auto &iter : immstat) {
            const ImmCount *immcnt = &iter.second;
            if (immcnt->count) {
                opt -= immcnt->count * immcnt->inflt * count;
            }
        }

        excess_by_isa_feat[MY_FEAT_IMMLOAD_OPT] += opt;
        return opt;
    }

    int64_t pushpop_pair_opt_sum_ex(TBCount *tbcnt) {
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        uint64_t count = tbcnt->count;

        for (int insni=1; insni<n_insns; insni++) {
            cs_insn *head = insns[insni-1];
            cs_insn *tail = insns[insni];
            if (head->id == X86_INS_PUSH && tail->id == X86_INS_PUSH ||
                head->id == X86_INS_POP  && tail->id == X86_INS_POP) {
                opt -= count;
                insni++;
            }
        }

        excess_by_isa_feat[MY_FEAT_PUSHPOP_PAIR_OPT] += opt;
        return opt;
    }

    int64_t pushpop_esp_opt_sum_ex(TBCount *tbcnt) {
        int64_t push_num = 0, pop_num = 0;
        int64_t opt = 0;
        cs_insn **insns = tbcnt->cs_insns;
        int n_insns = tbcnt->n_insns;
        int64_t count = tbcnt->count;
        for (int insni=0; insni<n_insns; insni++) {
            cs_insn *insn = insns[insni];
            if(insn->id == X86_INS_PUSH)
                push_num ++ ;
            if(insn->id == X86_INS_POP)
                pop_num ++ ;
        }
        opt -= (push_num + pop_num) * count;
        // 如果基本块中push, pop 数量不等，有一条改esp指针不能消掉
        if(push_num != pop_num) opt += count;
        excess_by_isa_feat[MY_FEAT_PUSHPOP_ELISION_OPT] += opt;
        return opt;
    }

    // in exagear and ideal, same addr will be calculate at the beginning of a TB
    int64_t addr_opt_sum_ex(TBCount *tbcnt) {
        typedef struct {
            std::list<int> insn_indices;
        } AddrCount;
        struct cmpAddr {
            bool operator()(const x86_op_mem *m1, const x86_op_mem *m2) const {
                if      (m1->base  < m2->base)  return true;
                else if (m1->base  > m2->base)  return false;

                if      (m1->index < m2->index) return true;
                else if (m1->index > m2->index) return false;

                if      (m1->scale < m2->scale) return true;
                else if (m1->scale > m2->scale) return false;
                else                            return false;
            }
        };
        typedef std::map<x86_op_mem *, AddrCount, cmpAddr> AddrStat;
        AddrStat addrstat;

        // build addrstat
        for (int insni=0; insni<tbcnt->n_insns; insni++) {
            cs_insn *insn = tbcnt->cs_insns[insni];
            cs_x86 *x86 = &insn->detail->x86;
            for (int opi=0; opi<x86->op_count; opi++) {
                cs_x86_op *op = &x86->operands[opi];
                if (op->type == X86_OP_MEM) {
                    x86_op_mem *addr = &op->mem;
                    if (addr_inflt(addr) || disp_inflt(insn, addr->disp))
                        addrstat[addr].insn_indices.push_back(insni);
                }
            }
        }

        // check whether potential same addr is modified by others
        // if potential same addr is modified, then discard
        for (auto &iter : addrstat) {
            const x86_op_mem *addr = iter.first;
            AddrCount *addrcnt = &iter.second;
            std::list<int> *insn_indices = &addrcnt->insn_indices;
            if (insn_indices->size() <= 1)
                continue;

            int base_gpr_idx = x86GPRidx(addr->base);
            int index_gpr_idx = x86GPRidx(addr->index);
            int insn_start_i = insn_indices->front();
            int insn_end_i = insn_indices->back();
            for (int insni = insn_start_i; insni<insn_end_i; insni++) {
                bool modified = false;

                cs_insn *insn = tbcnt->cs_insns[insni];
                cs_x86 *x86 = &insn->detail->x86;
                for (int opi=0; opi<x86->op_count; opi++) {
                    cs_x86_op *op = &x86->operands[opi];
                    if (op->type == X86_OP_REG && op->access & CS_AC_WRITE) {
                        int op_grp_idx = x86GPRidx(op->reg);
                        if (op_grp_idx == base_gpr_idx || op_grp_idx == index_gpr_idx) {
                            modified = true;
                            break;
                        }
                    }
                }

                if (modified) {
                    insn_indices->remove_if([insni](int i) { return insni<i;});
                    break;
                }
            }
        }

        // calculate opt from remaining addrstat
        int64_t opt = 0;
        for (auto &iter : addrstat) {
            const x86_op_mem *addr = iter.first;
            AddrCount *addrcnt = &iter.second;
            cs_insn dummy = {
                .address = 0,
            };
            std::list<int> *insn_indices = &addrcnt->insn_indices;
            // loop from second instruction
            for (std::list<int>::iterator indices_iter=std::next(insn_indices->begin());
                indices_iter != insn_indices->end(); indices_iter++) {
                int index = *indices_iter;
                opt -= (
                    disp_inflt(tbcnt->cs_insns[index], addr->disp) + addr_inflt(addr)
                    + subreg_inflt(addr->base) + subreg_inflt(addr->index)
                ) * tbcnt->count;
            }
        }
        excess_by_isa_feat[MY_FEAT_ADDR_PRECALC_OPT] += opt;
        return opt;
    }

public:
    virtual BaseExtra inflt(PCCount *pccnt) {
        cs_insn *insn = pccnt->insn;
        int base, extra;
        x86_insn id = x86_insn(insn->id);

        // calculate base
        switch (id) {
        case X86_INS_CALL:
            return BaseExtra(10, inflt_extra_jmp(pccnt, indirect_call_inflt));
        case X86_INS_RET:
            return BaseExtra(6, 0);
        case X86_INS_MOV: case X86_INS_MOVSX: case X86_INS_MOVSXD: case X86_INS_MOVZX: case X86_INS_MOVABS:
        case X86_INS_MOVSS: case X86_INS_MOVSD: case X86_INS_MOVUPS: case X86_INS_MOVUPD: case X86_INS_MOVAPS: case X86_INS_MOVAPD:
            return BaseExtra(1, inflt_extra_mov(pccnt));
        case X86_INS_LEA:
            return BaseExtra(1, inflt_extra_lea(pccnt));
        case X86_INS_JMP:
            return BaseExtra(1, inflt_extra_jmp(pccnt, indirect_jmp_inflt));
        case X86_INS_NOP: case X86_INS_ENDBR32: case X86_INS_ENDBR64:
            return BaseExtra(0,0);
        case X86_INS_ADD: case X86_INS_SUB:
        case X86_INS_AND: case X86_INS_OR: case X86_INS_XOR:
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_CMP:
            return BaseExtra(1, inflt_extra_cmp(pccnt));
        case X86_INS_TEST:
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_COMISS: case X86_INS_COMISD:
        case X86_INS_UCOMISS: case X86_INS_UCOMISD:
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_MUL: case X86_INS_MULX:
            return BaseExtra(3, inflt_extra_default(pccnt));
        case X86_INS_MULPD: case X86_INS_MULPS:
        case X86_INS_MULSD: case X86_INS_MULSS:
            return BaseExtra(1, inflt_extra_default(pccnt));
        case X86_INS_DIV:
            return BaseExtra(7, inflt_extra_default(pccnt)); 
        case X86_INS_IDIV:
            return BaseExtra(10, inflt_extra_default(pccnt)); 
        case X86_INS_DIVPD: case X86_INS_DIVPS: 
        case X86_INS_DIVSD: case X86_INS_DIVSS:
            return BaseExtra(1, inflt_extra_default(pccnt)); 
        default:
            return BaseExtra(-1, inflt_extra_default(pccnt));
            base = -1;  // base=-1, 表示不支持的指令，会输出，之后会改成1 
        }

        return BaseExtra(base, extra);
    }

    virtual int64_t opt(TBCount *tbcnt) {
        // int64_t immload = immload_opt_sum_ex(tbcnt);
        // return immload;
        return 0;
    }

    virtual int64_t pessi(TBCount *tbcnt) {
        return 0;
    }
};

#endif /* BT_HH */
