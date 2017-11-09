#ifndef BESS_MODULES_DYSCOPOLICYCENTER_H_
#define BESS_MODULES_DYSCOPOLICYCENTER_H_

#include "../module.h"

class DyscoPolicyCenter final : public Module {
 public:
	static const gate_idx_t kNumIGates = 0;
	static const gate_idx_t kNumOGates = 0;
	DyscoPolicyCenter();

	void set_test(int t) {
		teste = t;
	}
 private:
	int teste;
};

#endif //BESS_MODULES_DYSCOPOLICYCENTER_H_
