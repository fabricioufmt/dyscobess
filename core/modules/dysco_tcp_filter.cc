#include "dysco_tcp_filter.h"

void DyscoTcpFilter::ProcessBatch(bess::PacketBatch* batch) {
  bpf.igates = this->igates_;
  bpf.ogates = this->ogates_;
}


ADD_MODULE(DyscoTcpFilter, "dysco_tcp_filter", "classifies packet as TCP or non-TCP")
