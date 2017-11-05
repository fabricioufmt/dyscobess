#ifndef BESS_MODULES_DYSCOTCPFILTER_H_
#define BESS_MODULES_DYSCOTCPFILTER_H_

#include <pcap.h>

#include <vector>

#include "../module.h"
#include "../pb/module_msg.pb.h"
#include "bpf.h"

class DyscoTcpFilter final : public Module {
 public:
  static const gate_idx_t kNumIGates = 1;
  static const gate_idx_t kNumOGates = 2;
  
 DyscoTcpFilter() : Module() {
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
    bess::OGate* ogate = this->ogates_[0];
    Module* m_next = ogate->next();
    gate_idx_t igate_idx = ogate->igate_idx();
    DisconnectModules(0);
    bpf.ConnectModules(0, m_next, igate_idx);

    ogate = this->ogates_[1];
    m_next = ogate->next();
    igate_idx = ogate->igate_idx();
    DisconnectModules(1);
    bpf.ConnectModules(1, m_next, igate_idx);

    bess::IGate* igate = this->igates_[0];
    std::vector<Module*> modules;
    std::vector<gate_idx_t> ogates;
    for(const auto &o_gate : igate->ogates_upstream()) {
      modules.push_back(o_gate->module());
      ogates.push_back(o_gate->igate_idx());
    }
    DisconnectModulesUpstream(0);
    for(unsigned int i = 0; i < modules.size(); i++) {
      modules[i]->ConnectModules(ogates[i], &bpf, 0);
    }
  }
  
  //void ProcessBatch(bess::PacketBatch*) override;
 private:
  BPF bpf;
};

#endif // BESS_MODULES_DYSCOTCPFILTER_H_
