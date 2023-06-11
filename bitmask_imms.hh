#ifndef BITMASK_IMMS_HH
#define BITMASK_IMMS_HH 1
// Inspired by
//   https://dinfuehr.github.io/blog/encoding-of-immediate-values-on-aarch64/
//   https://stackoverflow.com/questions/30904718/range-of-immediate-values-in-armv8-a64-assembly/33265035#33265035

#include <stdint.h>
#include <set>

#define NUM_BITMASK_IMMS 5334
std::set<uint64_t> *bitmask_imms = nullptr;

void bitmask_imms_init(void) {
    if (bitmask_imms)
        return;
    bitmask_imms = new std::set<uint64_t>();

    uint64_t result;
    unsigned size, length, rotation, e;
    for (size = 2; size <= 64; size *= 2) {
        for (length = 1; length < size; ++length) {
            result = 0xffffffffffffffffULL >> (64 - length);
            for (e = size; e < 64; e *= 2)
                result |= result << e;
            for (rotation = 0; rotation < size; ++rotation) {
                bitmask_imms->insert(result);
                result = (result >> 63) | (result << 1);
            }
        }
    }
}

bool is_bitmask_imm(uint64_t imm) {
    auto search=bitmask_imms->find(imm);
    return search!=bitmask_imms->end();
}

#endif /* BITMASK_IMMS_HH */
