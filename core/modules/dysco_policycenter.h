#ifndef BESS_MODULES_DYSCOPOLICYCENTER_H_
#define BESS_MODULES_DYSCOPOLICYCENTER_H_

#include "../module.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"

using bess::utils::Ipv4;
using bess::utils::Tcp;

class DyscoPolicyCenter final : public Module {
 public:
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	DyscoPolicyCenter();

	bool add(Ipv4*, Tcp*, uint8_t*, int);
};

#endif //BESS_MODULES_DYSCOPOLICYCENTER_H_
