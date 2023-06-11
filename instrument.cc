#include <glib.h>
extern "C" {
#include <qemu-plugin.h>
}

#include "instrument.hh"

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static GHashTable *tbstat;

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb) {
    Instru_TBCount *tbcnt;
    uint64_t vaddr = qemu_plugin_tb_vaddr(tb);
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    uint64_t hash = vaddr ^ n_insns;

    tbcnt = (Instru_TBCount *)g_hash_table_lookup(tbstat, (gconstpointer)hash);
    if (!tbcnt) {
        tbcnt = new Instru_TBCount(n_insns);
        tbcnt->vaddr = vaddr;
        tbcnt->n_insns = n_insns;
        tbcnt->count = 0;

        for (int i = 0; i < n_insns; i++) {
            struct qemu_plugin_insn *qinsn = qemu_plugin_tb_get_insn(tb, i);
            Instru_Inst *insn = new Instru_Inst(qemu_plugin_insn_size(qinsn));
            insn->addr = qemu_plugin_insn_vaddr(qinsn);
            memcpy(insn->bytes, qemu_plugin_insn_data(qinsn), insn->n_bytes);

            tbcnt->insns[i] = insn;
        }
        g_hash_table_insert(tbstat, (gpointer)hash, (gpointer)tbcnt);
    }

    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64, &tbcnt->count, 1);
}

static void write_tbstat(void) {
    GString *report = g_string_new(NULL);
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, tbstat);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        uint64_t hash = (uint64_t)key;
        Instru_TBCount *tbcnt = (Instru_TBCount *)value;
        g_string_append(report, tbcnt->tostr()->str);
    }
    qemu_plugin_outs(report->str);
    g_string_free(report, true);
}

static void plugin_exit(qemu_plugin_id_t id, void *_) {
    write_tbstat();

    // clean
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, tbstat);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        uint64_t hash = (uint64_t)key;
        Instru_TBCount *tbcnt = (Instru_TBCount *)value;
        delete tbcnt;
    }
    g_hash_table_destroy(tbstat);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv) {
    // init hashtable
    tbstat = g_hash_table_new(NULL, g_direct_equal);

    qemu_plugin_outs(info->target_name);
    qemu_plugin_outs("\n");

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
