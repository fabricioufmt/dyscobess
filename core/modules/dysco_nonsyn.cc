#include "dysco_nonsyn.h"

DyscoNonSyn::DyscoNonSyn() : Module() {
}

void DyscoNonSyn::ProcessBatch(bess::PacketBatch* batch) {
  RunChooseModule(0, batch);
}

ADD_MODULE(DyscoNonSyn, "dysco_nonsyn", "processes TCP NON-SYN segment")
