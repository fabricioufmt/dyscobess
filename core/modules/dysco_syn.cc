#include "dysco_syn.h"

DyscoSyn::DyscoSyn() : Module() {
  bpf = new DyscoBPF();
}

void DyscoSyn::ProcessBatch(bess::PacketBatch* batch) {
  if(bpf->filters_.size() == 0)
    RunChooseModule(0, batch);
  
  RunChooseModule(0, batch);
}

ADD_MODULE(DyscoSyn, "dysco_syn", "processes TCP SYN fragment")
