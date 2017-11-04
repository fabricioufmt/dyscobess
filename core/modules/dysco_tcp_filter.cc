#include "dysco_tcp_filter.h"

void DyscoTcpFilter::ProcessBatch(bess::PacketBatch* batch) {
  bpf.igates() = igates_;
  bpf.ogates() = ogates_;
  batch = NULL;
}


ADD_MODULE(DyscoTcpFilter, "dysco_tcp_filter", "classifies packet as TCP or non-TCP")
