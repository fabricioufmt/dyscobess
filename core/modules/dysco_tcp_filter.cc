#include "dysco_tcp_filter.h"

DyscoTcpFilter::DyscoTcpFilter() : Module() {
  const bess::pb::BPFArg arg;
  arg.filter = "ip and tcp";
  arg.priority = 64;
}

void DyscoTcpFilter::ProcessBatch(bess::PacketBatch* batch) {
  batch = NULL;
}


ADD_MODULE(DyscoTcpFilter, "dysco_tcp_filter", "classifies packet as TCP or non-TCP")
