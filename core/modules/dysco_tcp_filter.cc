#include "dysco_tcp_filter.h"

void DyscoTcpFilter::ProcessBatch(bess::PacketBatch* batch) {
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
    Disconnect BPF gates
  */
  //bpf.DisconnectModules(0);
  //bpf.DisconnectModules(1);
  //bpf.DisconnectModulesUpstream(0); 
  
  /*
    Disconnect and new connect ogate 0
  */
  bess::OGate* ogate = ogates()[0];
  Module* m_next = ogate->next();
  gate_idx_t igate_idx = ogate->igate_idx();
  //DisconnectModules(0);
  bpf.ConnectModules(0, m_next, igate_idx);

  ogate = ogates()[1];
  m_next = ogate->next();
  igate_idx = ogate->igate_idx();
  //DisconnectModules(1);
  bpf.ConnectModules(1, m_next, igate_idx);
  /*
  bess::IGate* igate = igates()[0];
  std::vector<Module*> modules;
  std::vector<gate_idx_t> ogates;
  for(const auto &o_gate : igate->ogates_upstream()) {
    modules.push_back(o_gate->module());
    ogates.push_back(o_gate->igate_idx());
  }
  //DisconnectModulesUpstream(0);
  for(unsigned int i = 0; i < modules.size(); i++) {
    modules[i]->ConnectModules(ogates[i], &bpf, 0);
  }
*/
  bpf.ProcessBatch(batch);
}

ADD_MODULE(DyscoTcpFilter, "dysco_tcp_filter", "classifies packet as TCP or non-TCP")
