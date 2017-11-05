#include "dysco_synp.h"

DyscoSynP::DyscoSynP() : Module() {
}

void DyscoSynP::ProcessBatch(bess::PacketBatch* batch) {
  RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSynP, "dysco_synp", "processes TCP SYN with Payload fragment")
