#include "dysco_tcp_filter.h"

DyscoTcpFilter::DyscoTcpFilter() : Module() {
  /*
    Create BPF module
   */
  bess::pb::BPFArg arg;
  bess::pb::BPFArg::Filter* f1 = arg.add_filters();
  f1->set_priority(8);
  f1->set_filter("ip and tcp");
  f1->set_gate(0);
  bess::pb::BPFArg::Filter* f2 = arg.add_filters();
  f2->set_priority(4);
  f2->set_filter("not ip or not tcp");
  f2->set_gate(1);
  bpf.DeInit();
  bpf.Init(arg);

  /*
    Disconnect gates
   */
  DisconnectModules(0);
  DisconnectModules(1);
  DisconnectModulesUpstream(0);
  bpf.DisconnectModules(0);
  bpf.DisconnectModules(1);
  bpf.DisconnectModulesUpstream(0);  
}

void DyscoTcpFilter::ProcessBatch(bess::PacketBatch* batch) {
  batch->set_cnt(0);
}


ADD_MODULE(DyscoTcpFilter, "dysco_tcp_filter", "classifies packet as TCP or non-TCP")
