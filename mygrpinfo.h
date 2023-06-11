#ifndef MYGRPINFO_H
#define MYGRPINFO_H
#include <capstone/capstone.h>

typedef struct {
    char name[10];
    unsigned int n; // number of insts in this group
    #define GRP_INSTS_MAX 16
    unsigned int ids[GRP_INSTS_MAX]; // insts id in this group
} MyGroupInfo;

enum MyGroupId {
    MY_GRP_INVALID = 0,
    MY_GRP_BEGINING,

    MY_GRP_JCC = MY_GRP_BEGINING,
    MY_GRP_ADDSUB,
    MY_GRP_UNARY,
    MY_GRP_LOGIC,
    MY_GRP_SHIFTROT,
    MY_GRP_PUSHPOP,
    MY_GRP_CALLRET,
    MY_GRP_CMOVCC,
    MY_GRP_CMPTST,
    MY_GRP_SETCC,
    MY_GRP_MOVEXT,
    MY_GRP_BTNOP,
    MY_GRP_MOVSTR,
    MY_GRP_MOVFP,
    MY_GRP_MOVVEC,
    MY_GRP_ADDSUBFP,
    MY_GRP_ADDSUBVEC,
    MY_GRP_MULDIVFP,
    MY_GRP_COMIS,
    MY_GRP_ENDING,
};

MyGroupInfo mygrpsinfo[] = {
    [MY_GRP_INVALID] = {"invalid", 0, {}},
    [MY_GRP_JCC] = {"jcc", 16, {
        X86_INS_JAE, X86_INS_JA,  X86_INS_JBE, X86_INS_JB,
        X86_INS_JE,  X86_INS_JGE, X86_INS_JG,  X86_INS_JLE,
        X86_INS_JL,  X86_INS_JNE, X86_INS_JNO, X86_INS_JNP,
        X86_INS_JNS, X86_INS_JO,  X86_INS_JP,  X86_INS_JS
    }},
    [MY_GRP_ADDSUB] = {"addsub", 2, {
        X86_INS_ADD, X86_INS_SUB
    }},
    [MY_GRP_UNARY] = {"unary", 4, {
        X86_INS_NEG, X86_INS_INC, X86_INS_DEC, X86_INS_NOT
    }},
    [MY_GRP_LOGIC] = {"logic", 3, {
        X86_INS_AND, X86_INS_OR, X86_INS_XOR
    }},
    [MY_GRP_SHIFTROT] = {"shiftrot",4, {
        X86_INS_SHL, X86_INS_SHR, X86_INS_SAL, X86_INS_SAR,
        X86_INS_RCL, X86_INS_RCR, X86_INS_ROL, X86_INS_ROR
    }},
    [MY_GRP_PUSHPOP] = {"pushpop", 2, {
        X86_INS_PUSH, X86_INS_POP
    }},
    [MY_GRP_CALLRET] = {"callret", 2, {
        X86_INS_CALL, X86_INS_RET
    }},
    [MY_GRP_CMOVCC] = {"cmovcc", 16, {
        X86_INS_CMOVAE, X86_INS_CMOVA,  X86_INS_CMOVBE, X86_INS_CMOVB,
        X86_INS_CMOVE,  X86_INS_CMOVGE, X86_INS_CMOVG,  X86_INS_CMOVLE,
        X86_INS_CMOVL,  X86_INS_CMOVNE, X86_INS_CMOVNO, X86_INS_CMOVNP,
        X86_INS_CMOVNS, X86_INS_CMOVO,  X86_INS_CMOVP,  X86_INS_CMOVS
    }},
    [MY_GRP_CMPTST] = {"cmptst", 2, {
        X86_INS_CMP, X86_INS_TEST
    }},
    [MY_GRP_SETCC] = {"setcc", 16, {
        X86_INS_SETAE, X86_INS_SETA,  X86_INS_SETBE, X86_INS_SETB,
        X86_INS_SETE,  X86_INS_SETGE, X86_INS_SETG,  X86_INS_SETLE,
        X86_INS_SETL,  X86_INS_SETNE, X86_INS_SETNO, X86_INS_SETNP,
        X86_INS_SETNS, X86_INS_SETO,  X86_INS_SETP,  X86_INS_SETS
    }},
    [MY_GRP_MOVEXT] = {"movext", 3, {
        X86_INS_MOVSX, X86_INS_MOVSXD, X86_INS_MOVZX
    }},
    [MY_GRP_BTNOP] = {"btnop", 3, {
        X86_INS_NOP, X86_INS_ENDBR32, X86_INS_ENDBR64
    }},
    // TODO: string MOVSD has same capstone id as fp vector MOVSD
    //       which can be distinguish by instruction group
    [MY_GRP_MOVSTR] = {"movstr", 3, {
        X86_INS_MOVSB, X86_INS_MOVSW, X86_INS_MOVSQ,
    }},
    [MY_GRP_MOVFP] = {"movfp", 2, {
        X86_INS_MOVSS, X86_INS_MOVSD,
    }},
    [MY_GRP_MOVVEC] = {"movvec", 4, {
        X86_INS_MOVUPS, X86_INS_MOVUPD, X86_INS_MOVAPS, X86_INS_MOVAPD,
    }},
    [MY_GRP_ADDSUBFP] = {"addsubfp", 4, {
        X86_INS_ADDSS, X86_INS_ADDSD, X86_INS_SUBSS, X86_INS_SUBSD,
    }},
    [MY_GRP_ADDSUBVEC] = {"addsubvec", 4, {
        X86_INS_ADDPS, X86_INS_ADDPD, X86_INS_SUBPS, X86_INS_SUBPD,
    }},
    [MY_GRP_MULDIVFP] = {"muldivfp", 4, {
        X86_INS_MULSS, X86_INS_MULSD, X86_INS_DIVSS, X86_INS_DIVSD,
    }},
    [MY_GRP_COMIS] = {"comis", 4, {
        X86_INS_COMISS, X86_INS_COMISD, X86_INS_UCOMISS, X86_INS_UCOMISD,
    }},
};

bool isJcc(unsigned int id) {
    MyGroupInfo *jcc_grp_info = &mygrpsinfo[MY_GRP_JCC];
    for (int i=0; i<jcc_grp_info->n; i++) {
        if (jcc_grp_info->ids[i] == id)
            return true;
    }
    return false;
}

bool isJccNotOpt(unsigned int id) {
    MyGroupInfo jcc_grp_info = {"jccNotOpt", 6, {
        X86_INS_JS, X86_INS_JNS, X86_INS_JO, X86_INS_JNO, X86_INS_JP, X86_INS_JNP
    }};
    for (int i=0; i<jcc_grp_info.n; i++) {
        if (jcc_grp_info.ids[i] == id)
            return true;
    }
    return false;
}

bool isJccOpt(unsigned int id) {
    MyGroupInfo jcc_grp_info = {"optjcc", 10, {
        X86_INS_JAE, X86_INS_JA,  X86_INS_JBE, X86_INS_JB,
        X86_INS_JE,  X86_INS_JGE, X86_INS_JG,  X86_INS_JLE,
        X86_INS_JL,  X86_INS_JNE
    }};
    for (int i=0; i<jcc_grp_info.n; i++) {
        if (jcc_grp_info.ids[i] == id)
            return true;
    }
    return false;
}

bool isCmovcc(unsigned int id) {
    MyGroupInfo *cmovcc_grp_info = &mygrpsinfo[MY_GRP_CMOVCC];
    for (int i=0; i<cmovcc_grp_info->n; i++) {
        if (cmovcc_grp_info->ids[i] == id)
            return true;
    }
    return false;
}

bool isLogic(unsigned int id) {
    MyGroupInfo *logic_grp_info = &mygrpsinfo[MY_GRP_LOGIC];
    for (int i=0; i<logic_grp_info->n; i++) {
        if (logic_grp_info->ids[i] == id)
            return true;
    }
    return false;
}

bool isAddSub(unsigned int id) {
    MyGroupInfo *addsub_grp_info = &mygrpsinfo[MY_GRP_ADDSUB];
    for (int i=0; i<addsub_grp_info->n; i++) {
        if (addsub_grp_info->ids[i] == id)
            return true;
    }
    return false;
}

// bool isCmpTst(unsigned int id) {
//     MyGroupInfo *cmptst_grp_info = &mygrpsinfo[MY_GRP_CMPTST];
//     for (int i=0; i<cmptst_grp_info->n; i++) {
//         if (cmptst_grp_info->ids[i] == id)
//             return true;
//     }
//     return false;
// }

bool isComis(unsigned int id) {
    MyGroupInfo *cmptst_grp_info = &mygrpsinfo[MY_GRP_COMIS];
    for (int i=0; i<cmptst_grp_info->n; i++) {
        if (cmptst_grp_info->ids[i] == id)
            return true;
    }
    return false;
}

#define mygrpslen sizeof(mygrpsinfo)/sizeof(MyGroupInfo)
// https://stackoverflow.com/questions/9907160/how-to-convert-enum-names-to-string-in-c
#define ASSERT_ENUM_TO_STR(sarray, max) \
  typedef char assert_sizeof_##max[(sizeof(sarray)/sizeof(sarray[0]) == (max)) ? 1 : -1]
ASSERT_ENUM_TO_STR(mygrpsinfo, MY_GRP_ENDING);

static int x86GPRidx(x86_reg r) {
    switch (r) {
    case X86_REG_AL: case X86_REG_AH: case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX:
        return 0;
    case X86_REG_BL: case X86_REG_BH: case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX:
        return 1;
    case X86_REG_CL: case X86_REG_CH: case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX:
        return 2;
    case X86_REG_DL: case X86_REG_DH: case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX:
        return 3;
    case X86_REG_BPL: case X86_REG_BP: case X86_REG_EBP: case X86_REG_RBP:
        return 4;
    case X86_REG_SIL: case X86_REG_SI: case X86_REG_ESI: case X86_REG_RSI:
        return 5;
    case X86_REG_DIL: case X86_REG_DI: case X86_REG_EDI: case X86_REG_RDI:
        return 6;
    case X86_REG_SPL: case X86_REG_SP: case X86_REG_ESP: case X86_REG_RSP:
        return 7;
    case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D: case X86_REG_R8:
        return 8;
    case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D: case X86_REG_R9:
        return 9;
    case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D: case X86_REG_R10:
        return 10;
    case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D: case X86_REG_R11:
        return 11;
    case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D: case X86_REG_R12:
        return 12;
    case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D: case X86_REG_R13:
        return 13;
    case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D: case X86_REG_R14:
        return 14;
    case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D: case X86_REG_R15:
        return 15;
    default: return -1;
    }
}

static int x86XMMidx(x86_reg r) {
    switch (r) {
    case X86_REG_XMM0:  return 0;
    case X86_REG_XMM1:  return 1;
    case X86_REG_XMM2:  return 2;
    case X86_REG_XMM3:  return 3;
    case X86_REG_XMM4:  return 4;
    case X86_REG_XMM5:  return 5;
    case X86_REG_XMM6:  return 6;
    case X86_REG_XMM7:  return 7;
    case X86_REG_XMM8:  return 8;
    case X86_REG_XMM9:  return 9;
    case X86_REG_XMM10: return 10;
    case X86_REG_XMM11: return 11;
    case X86_REG_XMM12: return 12;
    case X86_REG_XMM13: return 13;
    case X86_REG_XMM14: return 14;
    case X86_REG_XMM15: return 15;
    default: return -1;
    }
}
static int x86DstXMMidx(cs_insn *insn) {
    cs_x86_op *dst_op = &insn->detail->x86.operands[0];
    if (dst_op->type != X86_OP_REG)
        return -1;
    return x86XMMidx(dst_op->reg);
}

#endif
