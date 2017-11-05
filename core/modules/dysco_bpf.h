#ifndef BESS_MODULES_DYSCOBPF_H_
#define BESS_MODULES_DYSCOBPF_H_

#include <vector>
#include <string>

using bpf_filter_func_t = u_int (*)(u_char *, u_int, u_int);

class DyscoBPF final {
 public:
  
  DyscoBPF() {}

 private:
  struct Filter {
#ifdef __x86_64
    bpf_filter_func_t func;
    size_t mmap_size;  // needed for munmap()
#else
    bpf_program il_code;
#endif
    int gate;
    int priority;     // higher number == higher priority
    std::string exp;  // original filter expression string
  };

  static bool Match(const Filter &, u_char *, u_int, u_int);

  std::vector<Filter> filters_;
};

#endif  // BESS_MODULES_DYSCOBPF_H_
