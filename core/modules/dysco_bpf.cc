#include "dysco_bpf.h"
#include "bpf.h"
//#define SNAPLEN 0xffff
static int bpf_jit_optimize(struct bpf_insn *prog, u_int nins) {
  int flags;
  u_int i;

  /* Do we return immediately? */
  if (BPF_CLASS(prog[0].code) == BPF_RET)
    return (BPF_JIT_FRET);

  for (flags = 0, i = 0; i < nins; i++) {
    switch (prog[i].code) {
      case BPF_LD | BPF_W | BPF_ABS:
      case BPF_LD | BPF_H | BPF_ABS:
      case BPF_LD | BPF_B | BPF_ABS:
      case BPF_LD | BPF_W | BPF_IND:
      case BPF_LD | BPF_H | BPF_IND:
      case BPF_LD | BPF_B | BPF_IND:
      case BPF_LDX | BPF_MSH | BPF_B:
        flags |= BPF_JIT_FPKT;
        break;
      case BPF_LD | BPF_MEM:
      case BPF_LDX | BPF_MEM:
      case BPF_ST:
      case BPF_STX:
        flags |= BPF_JIT_FMEM;
        break;
      case BPF_LD | BPF_W | BPF_LEN:
      case BPF_LDX | BPF_W | BPF_LEN:
        flags |= BPF_JIT_FLEN;
        break;
      case BPF_JMP | BPF_JA:
      case BPF_JMP | BPF_JGT | BPF_K:
      case BPF_JMP | BPF_JGE | BPF_K:
      case BPF_JMP | BPF_JEQ | BPF_K:
      case BPF_JMP | BPF_JSET | BPF_K:
      case BPF_JMP | BPF_JGT | BPF_X:
      case BPF_JMP | BPF_JGE | BPF_X:
      case BPF_JMP | BPF_JEQ | BPF_X:
      case BPF_JMP | BPF_JSET | BPF_X:
        flags |= BPF_JIT_FJMP;
        break;
    }
    if (flags == BPF_JIT_FLAG_ALL)
      break;
  }

  return (flags);
}
bool DyscoBPF::add_filter(std::string exp, int priority) {
  Filter filter;
  filter.priority = priority;
  filter.exp = exp;

  struct bpf_program il;
  if(pcap_compile_nopcap(SNAPLEN, DLT_EN10MB, &il, 1, PCAP_NETMASK_UNKNOWN) == -1)
    return false;

#ifdef __x86_64
  filter.func = bpf_jit_compile(il.bf_insns, il.bf_len, &filter.mmap_size);
  pcap_freecode(&il);
  if (!filter.func) {
    return false;
  }
#else
  filter.il_code = il;
#endif

  filters_.push_back(filter);

  std::sort(filters_.begin(), filters_.end(),
            [](const Filter &a, const Filter &b) {
              // descending order of priority number
              return b.priority < a.priority;
            });

  return true;
}

int* DyscoBPF::ProcessBatch1Filter(bess::PacketBatch* batch) {
  int cnt = batch->cnt();
  const Filter& filter = filters_[0];

  int* pouts = new int[cnt];
  memset(pouts, -1, cnt * sizeof(int));

  for(int i = 0; i < cnt; i++) {
    bess::Packet* pkt = batch->pkts()[i];

    if(Match(filter, pkt->head_data<uint8_t*>(), pkt->total_len(), pkt->head_len()))
      pouts[i] = 0;
    
  }

  return pouts;
}

int* DyscoBPF::ProcessBatch(bess::PacketBatch* batch) {
  int cnt = batch->cnt();
  int n_filters = filters_.size();
  
  if(cnt == 0 || n_filters == 0)
    return nullptr;

  if(n_filters == 1)
    return ProcessBatch1Filter(batch);

  int i, j;
  int* pouts = new int[cnt];
  for(i = 0; i < cnt; i++) {
    bess::Packet* pkt = batch->pkts()[i];

    for(j = 0; j < n_filters; j++) {
      if(Match(filters_[j], pkt->head_data<uint8_t*>(), pkt->total_len(), pkt->head_len())) {
	pouts[i] = j;
	break;
      }
    }
    if(j == n_filters)
      pouts[i] = -1;
  }

  return pouts;
}

inline bool DyscoBPF::Match(const Filter &filter, u_char *pkt, u_int wirelen,
                  u_int buflen) {
#ifdef __x86_64
  int ret = filter.func(pkt, wirelen, buflen);
#else
  int ret = bpf_filter(filter.il_code.bf_insns, pkt, wirelen, buflen);
#endif

  return ret != 0;
}
