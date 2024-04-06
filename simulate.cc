#include <capstone/capstone.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "ideal.hh"
#include "exagear.hh"
#include "rosetta.hh"
#include "latx.hh"
#include "qemu.hh"
#include "zen2.hh"
#include "haswell.hh"
#include "icelake.hh"
#include "instrument.hh"

enum BT_TYPE {
    BT_IDEAL,
    BT_EXAGEAR,
    BT_ROSETTA,
    BT_LATX,
    BT_QEMU,
    BT_ZEN2,
    BT_HASWELL,
    BT_ICELAKE,
};
BT_TYPE bt_type = BT_IDEAL;
BT *bt;

typedef struct {
    uint64_t count;
    uint64_t inflt_sum;
    GSList *pccnts;
    bool unknown;
    unsigned int id;
} InstCount;
InstCount inststat[X86_INS_ENDING + MY_GRP_ENDING] = {0};
const char *mygrp_name(csh cs_handle, unsigned int id) {
    if (id < X86_INS_ENDING) {
        return cs_insn_name(cs_handle, id);
    } else {
        unsigned int grp = id - X86_INS_ENDING;
        return mygrpsinfo[grp].name;
    }
}

FILE *file;
csh cs_handle;
static GHashTable *tbstat;

static bool verbose;

static void init(void) {
    // init capstone
    struct target_info {
        const char *name;
        cs_arch arch;
        cs_mode mode;
    };
    struct target_info all_archs[] = {
        { "aarch64",  CS_ARCH_ARM64, (cs_mode)(CS_MODE_LITTLE_ENDIAN)                },
        { "mips64el", CS_ARCH_MIPS,  (cs_mode)(CS_MODE_MIPS64|CS_MODE_LITTLE_ENDIAN) },
        { "mips64",   CS_ARCH_MIPS,  (cs_mode)(CS_MODE_MIPS64|CS_MODE_BIG_ENDIAN)    },
        { "i386",     CS_ARCH_X86,   (cs_mode)(CS_MODE_32)                           },
        { "x86_64",   CS_ARCH_X86,   (cs_mode)(CS_MODE_64)                           },
        { "riscv32",  CS_ARCH_RISCV, (cs_mode)(CS_MODE_RISCV32|CS_MODE_RISCVC)       },
        { "riscv64",  CS_ARCH_RISCV, (cs_mode)(CS_MODE_RISCV64|CS_MODE_RISCVC)       },
        { NULL }
    };

    char target_name[10];
    if (EOF == fscanf(file, "%s\n", target_name)) {
        perror("fscanf"); exit(-1);
    }
    struct target_info *target;
    cs_err err;
    for (int i = 0; all_archs[i].name; i++) {
        if (!strcmp(all_archs[i].name, target_name)) {
            target = &all_archs[i];
            err = cs_open(all_archs[i].arch, all_archs[i].mode, &cs_handle);
            if (!err) {
                cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
            } else {
                fprintf(stderr, "pcstat: csopen fail, %s\n", cs_strerror(err));
                abort();
            }
            break;
        }
    }
    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

    // init hashtable
    tbstat = g_hash_table_new(NULL, g_direct_equal);

    // init inststat
    for (int i=0; i<X86_INS_ENDING+MY_GRP_ENDING; i++)
        inststat[i].id = i;

    // init BT instance
    switch (bt_type) {
    case BT_IDEAL:
        bt = new Ideal();
        break;
    case BT_EXAGEAR:
        bt = new Exagear();
        break;
    case BT_ROSETTA:
        bt = new Rosetta();
        break;
    case BT_LATX:
        bt = new Latx();
        break;
    case BT_QEMU:
        bt = new Qemu();
        break;
    case BT_ZEN2:
        bt = new Zen2();
        break;
    case BT_HASWELL:
        bt = new Haswell();
        break;
    case BT_ICELAKE:
        bt = new Icelake();
        break;
    }
}

static void analyse_output(void) {
    GHashTableIter iter;
    gpointer key, value;
    GHashTable *pcstat = g_hash_table_new(NULL, g_direct_equal);

    // build pcstat from tbstat and get sum
    // calculate opt
    int64_t overall_inflt_sum = 0;
    uint64_t sum = 0;
    g_hash_table_iter_init(&iter, tbstat);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        uint64_t hash = (uint64_t)key;
        TBCount *tbcnt = (TBCount *)value;

        overall_inflt_sum += bt->opt(tbcnt);
        overall_inflt_sum += bt->pessi(tbcnt);

        for (int i = 0; i < tbcnt->n_insns; i++) {
            uint64_t vaddr = tbcnt->cs_insns[i]->address;
            PCCount *pccnt =
                (PCCount *)g_hash_table_lookup(pcstat, (gconstpointer)vaddr);
            if (pccnt) {
                pccnt->count += tbcnt->count;
            } else {
                pccnt = g_new0(PCCount, 1);
                pccnt->vaddr = vaddr;
                pccnt->count = tbcnt->count;
                pccnt->insn = tbcnt->cs_insns[i];
                g_hash_table_insert(pcstat, (gpointer)vaddr, (gpointer)pccnt);
            }
        }
    }

    g_hash_table_iter_init(&iter, tbstat);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        uint64_t hash = (uint64_t)key;
        TBCount *tbcnt = (TBCount *)value;
        sum += tbcnt->count * tbcnt->n_insns;
    }

    // build inststat
    g_hash_table_iter_init(&iter, pcstat);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        PCCount *pccnt = (PCCount *)value;
        unsigned int id = pccnt->insn->id;
        InstCount *instcnt = &inststat[id];
        instcnt->count += pccnt->count;

        BaseExtra base_extra = bt->inflt(pccnt);
        if (base_extra.first == -1) {
            base_extra.first = 1;
            instcnt->unknown = true;
        }
        pccnt->inflt = base_extra.first + base_extra.second;
        instcnt->inflt_sum += pccnt->inflt * pccnt->count;

        instcnt->pccnts = g_slist_prepend(instcnt->pccnts, pccnt);
    }

    // map insts to my group
    for (int grp=MY_GRP_BEGINING; grp<MY_GRP_ENDING; grp++) {
        MyGroupInfo *grpinfo = &mygrpsinfo[grp];
        for (int i=0; i<grpinfo->n; i++) {
            unsigned int id = grpinfo->ids[i];

            InstCount *ic_src = &inststat[id];
            InstCount *ic_dst = &inststat[X86_INS_ENDING + grp];

            ic_dst->count += ic_src->count;
            ic_dst->inflt_sum += ic_src->inflt_sum;
            ic_dst->pccnts = g_slist_concat(ic_dst->pccnts, ic_src->pccnts);
            ic_dst->unknown |= ic_src->unknown;

            ic_src->count = 0;
            ic_src->inflt_sum = 0;
            ic_src->pccnts = NULL;
            ic_src->unknown = false;
        }
    }

    // sort inststat as instseq, calc inflt_sum by the way
    GSequence *instseq = g_sequence_new(NULL);
    for (unsigned int id=0; id<X86_INS_ENDING+MY_GRP_ENDING; id++) {
        InstCount *instcnt = &inststat[id];
        if (instcnt->count) {
            overall_inflt_sum += instcnt->inflt_sum;

            g_sequence_insert_sorted(instseq, (gpointer)instcnt,
                [](gconstpointer a, gconstpointer b, gpointer _) {
                    InstCount *ica = (InstCount *)a;
                    InstCount *icb = (InstCount *)b;
                    /* uint64_t excessa = ica->inflt_sum > ica->count ? */
                    /*     ica->inflt_sum - ica->count : 0; */
                    /* uint64_t excessb = icb->inflt_sum > icb->count ? */
                    /*     icb->inflt_sum - icb->count : 0; */
                    /* if (excessa < excessb) return -1; */
                    /* else if (excessa == excessb) return 0; */
                    /* else return 1; */
                    if (ica->inflt_sum < icb->inflt_sum) return -1;
                    else if (ica->inflt_sum == icb->inflt_sum) return 0;
                    else return 1;
                },
                NULL
            );

            // sort pccnts by descending
            instcnt->pccnts = g_slist_sort(instcnt->pccnts,
                [](gconstpointer a, gconstpointer b) {
                    PCCount *pcca = (PCCount *)a;
                    PCCount *pccb = (PCCount *)b;
                    uint64_t excessa = pcca->inflt > 1 ?
                        (pcca->inflt - 1) * pcca->count : 0;
                    uint64_t excessb = pccb->inflt > 1 ?
                        (pccb->inflt - 1) * pccb->count : 0;
                    if (excessa < excessb) return 1;
                    else if (excessa == excessb) return 0;
                    else return -1;
                }
            );
        }
    }
    double overall_inflt = 1.0 * overall_inflt_sum / sum;

    // print instseq (sorted inststat)
    GString *report = g_string_new(NULL);
    for (GSequenceIter *seqi = g_sequence_get_begin_iter(instseq);
            !g_sequence_iter_is_end(seqi);
            seqi = g_sequence_iter_next(seqi)) {
        InstCount *instcnt = (InstCount *)g_sequence_get(seqi);
        unsigned int id = instcnt->id;
        if (instcnt->count) {
            double inflt = 1.0 * instcnt->inflt_sum / instcnt->count;
            double freq_percent = 100.0 * instcnt->count / sum;

            if (instcnt->unknown)
                g_string_append_printf(report, "Unknown inst %s\n", mygrp_name(cs_handle, id));
            g_string_append_printf(report, "%s %ld * %.4f %.2f%% %.4f\n",
                    mygrp_name(cs_handle, id), instcnt->count, inflt, freq_percent,
                    1.0 * inflt * instcnt->count / sum);
            if (verbose) {
                for (GSList *ele=instcnt->pccnts; ele; ele=g_slist_next(ele)) {
                    PCCount *pccnt = (PCCount *)ele->data;

                    char mcstr[48]; // machine code string
                    cs_insn *insn = pccnt->insn;
                    for (int i=0; i<insn->size; i++) {
                        sprintf(mcstr+i*2, "%02x", insn->bytes[i]);
                    }

                    g_string_append_printf(report, "    %lx %ld * %ld %.2f%% %s %s %s\n",
                            pccnt->vaddr,
                            pccnt->count, pccnt->inflt, 100.0 * pccnt->count / sum,
                            mcstr, insn->mnemonic, insn->op_str);

                    g_string_append_printf(report, "        ");
                    for (int i=0; i<insn->detail->x86.op_count; i++) {
                        cs_x86 *x86 = &insn->detail->x86;
                        cs_x86_op *op = &x86->operands[i];
                        if (op->type == X86_OP_MEM) {
                            g_string_append_printf(report, "disp_%d %lx ",
                                x86->encoding.disp_size, op->mem.disp
                            );
                        }
                        if (op->type == X86_OP_IMM) {
                            g_string_append_printf(report, "imm_%d %lx ",
                                x86->encoding.imm_size, op->imm
                            );
                        }
                    }
                    g_string_append_printf(report, "\n");
                    for (size_t i = MY_FEAT_BEGINING; i < MY_FEAT_ENDING; i++) {
                        if (pccnt->feats[i]) {
                            g_string_append_printf(report, "        %s %x\n",
                                MyBTFeatStr[i], pccnt->feats[i]);
                        }
                    }
                }
            }
        }
    }

    for (int i=MY_FEAT_BEGINING; i<MY_FEAT_ENDING; i++) {
        g_string_append_printf(report, "%s %.4f\n",
                MyBTFeatStr[i], 1.0*excess_by_isa_feat[i]/sum);
    }
    g_string_append_printf(report, "insts %ld inflation %ld %.4f\n",
            sum, overall_inflt_sum, overall_inflt);

    printf("%s", report->str);

    // clean pcstat
    g_hash_table_iter_init(&iter, pcstat);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        PCCount *pccnt = (PCCount *)value;
        g_free(pccnt);
    }
    g_hash_table_destroy(pcstat);

    // clean instseq
    g_sequence_free(instseq);

    g_string_free(report, TRUE);
}

static void clean(void) {
    // clean pcstat and capstone
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, tbstat);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        TBCount *tbcnt = (TBCount *)value;
        for (int i = 0; i < tbcnt->n_insns; i++) {
            cs_free(tbcnt->cs_insns[i], 1);
        }
        free(tbcnt->cs_insns);
        g_free(tbcnt);
    }
    g_hash_table_destroy(tbstat);
    cs_close(&cs_handle);

    // clean BT instance
    delete bt;
}

static void read_tbstat() {
    while (!feof(file)) {
        Instru_TBCount *instru_tbcnt = new Instru_TBCount(file);

        TBCount *tbcnt = g_new0(TBCount, 1);
        tbcnt->count = instru_tbcnt->count;
        tbcnt->vaddr = instru_tbcnt->vaddr;
        tbcnt->n_insns = instru_tbcnt->n_insns;
        tbcnt->cs_insns = (cs_insn **)malloc(sizeof(cs_insn *) * tbcnt->n_insns);

        for (int i=0; i<tbcnt->n_insns; i++) {
            Instru_Inst *instru_insn = instru_tbcnt->insns[i];
            cs_disasm(cs_handle,
                instru_insn->bytes, instru_insn->n_bytes, instru_insn->addr,
                1, &(tbcnt->cs_insns[i])
            );
        }

        uint64_t hash = tbcnt->vaddr ^ tbcnt->n_insns;
        g_hash_table_insert(tbstat, (gpointer)hash, (gpointer)tbcnt);

        delete instru_tbcnt;
    }
}

void usage(void) {
    printf("Usage: de-flate [-h] [-v] -f <trace file> [-t <bt>]\n");
    printf("  -h: print this help\n");
    printf("  -v: verbose\n");
    printf("  -f <trace file>: the path to the trace file, generated by instrument.so\n");
    printf("  -t <bt>: binary translator type: ideal(default), exagear, rosetta, latx, qemu\n");
    exit(0);
}
int main(int argc, char **argv) {
    {int c; while ((c = getopt(argc, argv, "hvf:t:")) != -1) {
        switch (c) {
        case 'h':
            usage();
        break;
        case 'v':
            verbose = true;
        break;
        case 'f':
            file = fopen(optarg, "r");
            if (file == NULL) {
                perror("fopen");
                exit(-1);
            }
        break;
        case 't':
            if (g_strcmp0(optarg, "exagear") == 0) {
                bt_type = BT_EXAGEAR;
            } else if (g_strcmp0(optarg, "rosetta") == 0) {
                bt_type = BT_ROSETTA;
            } else if (g_strcmp0(optarg, "latx") == 0) {
                bt_type = BT_LATX;
            } else if (g_strcmp0(optarg, "qemu") == 0) {
                bt_type = BT_QEMU;
            } else if (g_strcmp0(optarg, "zen2") == 0) {
                bt_type = BT_ZEN2;
            } else if (g_strcmp0(optarg, "haswell") == 0) {
                bt_type = BT_HASWELL;
            } else if (g_strcmp0(optarg, "icelake") == 0) {
                bt_type = BT_ICELAKE;
            } else {
                bt_type = BT_IDEAL;
            }
        break;
        }
    }}
    if (file == NULL) usage();

    init();
    read_tbstat();
    analyse_output();
    clean();

    return 0;
}
