#include "dysco_tcp_filter.h"

DyscoTcpFilter::DyscoTcpFilter() : Module() {
  //const bess::pb::BPFArg arg;
  //arg.filters.filter = "ip and tcp";
  //arg.filters.priority = 64;
  bpf.add(filters=[{"priority":8, "filter": "ip and tcp", "gate": 1}]);
  bpf.add(filters=[{"priority":4, "filter": "not ip or not tcp", "gate": 0}])
}

void DyscoTcpFilter::ProcessBatch(bess::PacketBatch* batch) {
  batch = NULL;
}


ADD_MODULE(DyscoTcpFilter, "dysco_tcp_filter", "classifies packet as TCP or non-TCP")
