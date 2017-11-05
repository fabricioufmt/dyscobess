#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>

#include "dysco_bpf.h"

inline bool DyscoBPF::Match(const Filter &filter, u_char *pkt, u_int wirelen,
                  u_int buflen) {
#ifdef __x86_64
  int ret = filter.func(pkt, wirelen, buflen);
#else
  int ret = bpf_filter(filter.il_code.bf_insns, pkt, wirelen, buflen);
#endif

  return ret != 0;
}
