#include "dysco_tcp_filter.h"

DyscoTcpFilter::DyscoTcpFilter() : Module() {
  bess::pb::BPFArg arg;
  bess::pb::BPFArg::Filter f1, f2;
  f1.set_priority(8);
  f1.set_filter("ip and tcp");
  f1.set_gate(0);
  f2.set_priority(4);
  f2.set_filter("not ip or not tcp");
  f2.set_gate(1);

  bess::pb::BPFArg::Filter* filters = arg.filters();
}

void DyscoTcpFilter::ProcessBatch(bess::PacketBatch* batch) {
  batch = NULL;
}


ADD_MODULE(DyscoTcpFilter, "dysco_tcp_filter", "classifies packet as TCP or non-TCP")
