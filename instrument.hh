#include <stdint.h> /* *int*_t */
#include <stdlib.h> /* malloc, free */
#include <glib.h> /* GString */
#include <stdio.h>

class Instru_Inst {
#define PATTERN1 "    %lx %hhd"
#define PATTERN2 " %02hhx"
public:
    uint64_t addr;
    uint8_t n_bytes;
    uint8_t *bytes;

    Instru_Inst(uint8_t n_bytes) {
        this->n_bytes = n_bytes;
        bytes = (uint8_t *)malloc(sizeof(uint8_t) * n_bytes);
    }
    Instru_Inst(FILE *file) {
        if (EOF == fscanf(file, PATTERN1, &addr, &n_bytes)) {
            perror("fscanf"); exit(-1);
        }
        bytes = (uint8_t *)malloc(sizeof(uint8_t) * n_bytes);
        for (int i=0; i<n_bytes; i++) {
            if (EOF == fscanf(file, PATTERN2, bytes+i)) {
                perror("fscanf"); exit(-1);
            }
        }
        if (EOF == fscanf(file, "\n")) {
            perror("fscanf"); exit(-1);
        }
    }
    ~Instru_Inst(void) {if (bytes) {
        free(bytes);
        bytes = NULL;
    }}

    GString *tostr(void) {
        GString *str = g_string_new(NULL);
        g_string_append_printf(str, PATTERN1, addr, n_bytes);
        for (int i=0; i<n_bytes; i++) {
            g_string_append_printf(str, PATTERN2, bytes[i]);
        }
        g_string_append_printf(str, "\n");
        return str;
    }
#undef PATTERN1
#undef PATTERN2
};

class Instru_TBCount {
#define PATTERN "%ld %lx %d\n"
public:
    uint64_t count;
    uint64_t vaddr;
    uint32_t n_insns;
    Instru_Inst **insns;

    Instru_TBCount(uint32_t n_insns) {
        this->n_insns = n_insns;
        insns = (Instru_Inst **)malloc(sizeof(Instru_Inst *) * n_insns);
    }
    Instru_TBCount(FILE *file) {
        if (EOF == fscanf(file, PATTERN, &count, &vaddr, &n_insns)) {
            perror("fscanf"); exit(-1);
        }
        insns = (Instru_Inst **)malloc(sizeof(Instru_Inst *) * n_insns);
        for (int i=0; i<n_insns; i++)
            insns[i] = new Instru_Inst(file);
    }
    ~Instru_TBCount(void) {if (insns) {
        for (int i=0; i<n_insns; i++) {
            delete insns[i];
        }
        free(insns);
        insns = NULL;
    }}

    GString *tostr(void) {
        GString *str = g_string_new(NULL);
        g_string_append_printf(str, PATTERN, count, vaddr, n_insns);
        for (int i=0; i<n_insns; i++)
            g_string_append(str, insns[i]->tostr()->str);
        return str;
    }
#undef PATTERN
};
