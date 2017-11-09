#include "dysco_policycenter.h"

DyscoPolicyCenter::DyscoPolicyCenter() : Module() {

}

bool DyscoPolicyCenter::add(Ipv4* ip, Tcp* tcp, uint8_t* payload, int payload_len) {
	return true;
}

ADD_MODULE(DyscoPolicyCenter, "dysco_policycenter", "Dysco core")
