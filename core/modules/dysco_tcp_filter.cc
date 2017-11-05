#include "dysco_tcp_filter.h"

DyscoTcpFilter::DyscoTcpFilter() : Module() {
  bpf = new DyscoBPF();
  bpf->add_filter("ip and tcp", 8);
}

void DyscoTcpFilter::ProcessBatch(bess::PacketBatch* batch) {
  const DyscoBPF::Filter &filter = bpf->filters_[0];

  bess::PacketBatch out_batches[2];
  bess::Packet **ptrs[2];

  ptrs[0] = out_batches[0].pkts();
  ptrs[1] = out_batches[1].pkts();

  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    if (bpf->Match(, pkt->head_data<u_char *>(), pkt->total_len(),
              pkt->head_len())) {
      *(ptrs[1]++) = pkt;
    } else {
      *(ptrs[0]++) = pkt;
    }
  }

  out_batches[0].set_cnt(ptrs[0] - out_batches[0].pkts());
  out_batches[1].set_cnt(ptrs[1] - out_batches[1].pkts());

  RunChooseModule(0, &out_batches[0]);
  RunChooseModule(1, &out_batches[1]);
  /*
  int cnt = batch->cnt();
  int n_filters = filters_.size();
  
  if(cnt == 0 || n_filters == 0)
    return nullptr;

  if(n_filters == 1)
    return ProcessBatch1Filter(batch);

  int i, j;
  int* pouts = new int[cnt];
  for(i = 0; i < cnt; i++) {
    bess::Packet* pkt = batch->pkts()[i];

    for(j = 0; j < n_filters; j++) {
      if(Match(filters_[j], pkt->head_data<uint8_t*>(), pkt->total_len(), pkt->head_len())) {
	pouts[i] = j;
	break;
      }
    }
    if(j == n_filters)
      pouts[i] = -1;
  }

  return pouts;

  
  int* pouts = bpf->ProcessBatch(batch);

  bess::PacketBatch out_batches[2];
  bess::Packet** ptrs[2];

  ptrs[0] = 
  
    Create BPF module
  
  bess::pb::BPFArg arg;
  bess::pb::BPFArg::Filter* f1 = arg.add_filters();
  f1->set_priority(8);
  f1->set_filter("ip and tcp");
  f1->set_gate(0);
  bess::pb::BPFArg::Filter* f2 = arg.add_filters();
  f2->set_priority(4);
  f2->set_filter("not ip or not tcp");
  f2->set_gate(1);
  bpf = new BPF();
  bpf->DeInit();
  bpf->Init(arg);

  bess::pb::CreateModuleRequest request;
  bess::pb::CreateModuleRequest response;

  request.set_name("dyscobpf0");
  request.set_mclass("BPF");
  
  CreateModule(NULL, &request, &response);
    Disconnect BPF gates
  
  //printf("(BPF)IN: %d == OUT: %d\n", bpf.module_builder()->NumIGates(), bpf.module_builder()->NumOGates());
  printf("(DYS)IN: %d == OUT: %d\n", module_builder()->NumIGates(), module_builder()->NumOGates());
  //bpf.DisconnectModules(0);
  //bpf.DisconnectModules(1);
  //bpf.DisconnectModulesUpstream(0); 
  
    Disconnect and new connect ogate 0
  
  bess::OGate* ogate = ogates()[0];
  Module* m_next = ogate->next();
  gate_idx_t igate_idx = ogate->igate_idx();
  //DisconnectModules(0);
  //bpf.ConnectModules(0, m_next, igate_idx);
  bpf.ConnectModules(bpf.ogates()[0]->igate_idx(), m_next, igate_idx);
  
  ogate = ogates()[1];
  m_next = ogate->next();
  igate_idx = ogate->igate_idx();
  //DisconnectModules(1);
  //bpf.ConnectModules(1, m_next, igate_idx);
  bpf.ConnectModules(bpf.ogates()[1]->igate_idx(), m_next, igate_idx);
  
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

  bpf->ProcessBatch(batch);
  */
}

ADD_MODULE(DyscoTcpFilter, "dysco_tcp_filter", "classifies packet as TCP or non-TCP")
