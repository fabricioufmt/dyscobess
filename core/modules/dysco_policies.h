#ifndef BESS_MODULES_DYSCOPOLICIES_H_
#define BESS_MODULES_DYSCOPOLICIES_H_

#include <pcap.h>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>

#include "../module.h"

using bpf_filter_func_t = u_int (*)(u_char *, u_int, u_int);

class DyscoPolicies {
 public:
	DyscoPolicies() {}
  
	struct Filter {
#ifdef __x86_64
		bpf_filter_func_t func;
		size_t mmap_size;  // needed for munmap()
#else
		bpf_program il_code;
#endif
		uint32_t priority;
		std::string exp;
		uint32_t* sc;
		uint32_t sc_len;
	};
	
	bool Match(const Filter &, u_char *, u_int, u_int);
	std::vector<Filter> filters_;

	bool add_filter(uint32_t, std::string, uint32_t*, uint32_t);
	Filter* match_policy(bess::Packet*);
};

#endif  // BESS_MODULES_DYSCOPOLICIES_H_
