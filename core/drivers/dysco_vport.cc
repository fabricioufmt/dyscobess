#include "dysco_vport.h"

#include <fcntl.h>
#include <libgen.h>
#include <sched.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <rte_config.h>
#include <rte_malloc.h>

#include "../message.h"
#include "../utils/format.h"

/* TODO: Unify vport and vport_native */

#define SLOTS_PER_LLRING 256

#define REFILL_LOW 16
#define REFILL_HIGH 32

/* This watermark is to detect congestion and cache bouncing due to
 * head-eating-tail (needs at least 8 slots less then the total ring slots).
 * Not sure how to tune this... */
#define SLOTS_WATERMARK ((SLOTS_PER_LLRING >> 3) * 7) /* 87.5% */

/* Disable (0) single producer/consumer mode for default */
#define SINGLE_P 0
#define SINGLE_C 0

#define ROUND_TO_64(x) ((x + 32) & (~0x3f))

static inline int find_next_nonworker_cpu(int cpu) {
	do {
		cpu = (cpu + 1) % sysconf(_SC_NPROCESSORS_ONLN);
	} while (is_worker_core(cpu));
	return cpu;
}

static void refill_tx_bufs(struct llring *r) {
	bess::Packet *pkts[REFILL_HIGH];
	phys_addr_t objs[REFILL_HIGH];

	int deficit;
	int ret;

	int curr_cnt = llring_count(r);

	if (curr_cnt >= REFILL_LOW)
		return;

	deficit = REFILL_HIGH - curr_cnt;

	ret = bess::Packet::Alloc((bess::Packet **)pkts, deficit, 0);
	if (ret == 0)
		return;

	for (int i = 0; i < ret; i++)
		objs[i] = pkts[i]->paddr();

	ret = llring_mp_enqueue_bulk(r, objs, ret);
	DCHECK_EQ(ret, 0);
}

static void drain_sn_to_drv_q(struct llring *q) {
	/* sn_to_drv queues contain physical address of packet buffers */
	for (;;) {
		phys_addr_t paddr;
		bess::Packet *snb;
		int ret;

		ret = llring_mc_dequeue(q, &paddr);
		if (ret)
			break;

		snb = bess::Packet::from_paddr(paddr);
		if (!snb) {
			LOG(ERROR) << "from_paddr(" << paddr << ") failed";
			continue;
		}

		bess::Packet::Free(snb);
	}
}

static void drain_drv_to_sn_q(struct llring *q) {
	/* sn_to_drv queues contain virtual address of packet buffers */
	for (;;) {
		phys_addr_t paddr;
		int ret;

		ret = llring_mc_dequeue(q, &paddr);
		if (ret)
			break;

		bess::Packet::Free(bess::Packet::from_paddr(paddr));
	}
}

static void reclaim_packets(struct llring *ring) {
	phys_addr_t objs[bess::PacketBatch::kMaxBurst];
	bess::Packet *pkts[bess::PacketBatch::kMaxBurst];
	int ret;

	for (;;) {
		ret = llring_mc_dequeue_burst(ring, objs, bess::PacketBatch::kMaxBurst);
		if (ret == 0)
			break;
		for (int i = 0; i < ret; i++) {
			pkts[i] = bess::Packet::from_paddr(objs[i]);
		}
		bess::Packet::Free(pkts, ret);
	}
}

static CommandResponse docker_container_pid(const std::string &cid,
                                            int *container_pid) {
	char buf[1024];

	FILE *fp;

	int ret;
	int exit_code;

	if (cid.length() == 0)
		return CommandFailure(EINVAL,
				      "field 'docker' should be "
				      "a containder ID or name in string");

	ret = snprintf(buf, static_cast<int>(sizeof(buf)),
		       "docker inspect --format '{{.State.Pid}}' "
		       "%s 2>&1",
		       cid.c_str());
	if (ret >= static_cast<int>(sizeof(buf)))
		return CommandFailure(EINVAL,
				      "The specified Docker "
				      "container ID or name is too long");

	fp = popen(buf, "r");
	if (!fp) {
		return CommandFailure(
				      ESRCH, "Command 'docker' is not available. (not installed?)");
	}

	ret = fread(buf, 1, sizeof(buf) - 1, fp);
	if (ret == 0)
		return CommandFailure(ENOENT,
				      "Cannot find the PID of "
				      "container %s",
				      cid.c_str());

	buf[ret] = '\0';

	ret = pclose(fp);
	exit_code = WEXITSTATUS(ret);

	if (exit_code != 0 || sscanf(buf, "%d", container_pid) == 0) {
		return CommandFailure(ESRCH, "Cannot find the PID of container %s",
				      cid.c_str());
	}

	return CommandSuccess();
}

static int next_cpu;

/* Free an allocated bar, freeing resources in the queues */
void DyscoVPort::FreeBar() {
	int i;
	struct sn_conf_space *conf = static_cast<struct sn_conf_space *>(bar_);

	for (i = 0; i < conf->num_txq; i++) {
		drain_drv_to_sn_q(inc_qs_[i].drv_to_sn);
		drain_sn_to_drv_q(inc_qs_[i].sn_to_drv);
	}

	for (i = 0; i < conf->num_rxq; i++) {
		drain_drv_to_sn_q(inc_qs_[i].drv_to_sn);
		drain_sn_to_drv_q(inc_qs_[i].sn_to_drv);
	}

	rte_free(bar_);
}

void *DyscoVPort::AllocBar(struct tx_queue_opts *txq_opts,
                      struct rx_queue_opts *rxq_opts) {
	int bytes_per_llring;
	int total_bytes;

	void *bar;
	struct sn_conf_space *conf;
	char *ptr;

	int i;

	bytes_per_llring = llring_bytes_with_slots(SLOTS_PER_LLRING);

	total_bytes = ROUND_TO_64(sizeof(struct sn_conf_space));
	total_bytes += num_queues[PACKET_DIR_INC] * 2 * ROUND_TO_64(bytes_per_llring);
	total_bytes += num_queues[PACKET_DIR_OUT] *
		(ROUND_TO_64(sizeof(struct sn_rxq_registers)) +
		 2 * ROUND_TO_64(bytes_per_llring));

	VLOG(1) << "BAR total_bytes = " << total_bytes;
	bar = rte_zmalloc(nullptr, total_bytes, 64);
	DCHECK(bar);

	conf = reinterpret_cast<struct sn_conf_space *>(bar);

	conf->bar_size = total_bytes;
	conf->netns_fd = netns_fd_;
	conf->container_pid = container_pid_;

	strncpy(conf->ifname, ifname_, IFNAMSIZ);

	bess::utils::Copy(conf->mac_addr, mac_addr, ETH_ALEN);

	conf->num_txq = num_queues[PACKET_DIR_INC];
	conf->num_rxq = num_queues[PACKET_DIR_OUT];
	conf->link_on = 1;
	conf->promisc_on = 1;

	conf->txq_opts = *txq_opts;
	conf->rxq_opts = *rxq_opts;

	ptr = (char *)(conf);
	ptr += ROUND_TO_64(sizeof(struct sn_conf_space));

	/* See sn_common.h for the llring usage */

	for (i = 0; i < conf->num_txq; i++) {
		/* Driver -> BESS */
		llring_init(reinterpret_cast<struct llring *>(ptr), SLOTS_PER_LLRING,
			    SINGLE_P, SINGLE_C);
		inc_qs_[i].drv_to_sn = reinterpret_cast<struct llring *>(ptr);
		ptr += ROUND_TO_64(bytes_per_llring);

		/* BESS -> Driver */
		llring_init(reinterpret_cast<struct llring *>(ptr), SLOTS_PER_LLRING,
			    SINGLE_P, SINGLE_C);
		refill_tx_bufs(reinterpret_cast<struct llring *>(ptr));
		inc_qs_[i].sn_to_drv = reinterpret_cast<struct llring *>(ptr);
		ptr += ROUND_TO_64(bytes_per_llring);
	}

	for (i = 0; i < conf->num_rxq; i++) {
		/* RX queue registers */
		out_qs_[i].rx_regs = reinterpret_cast<struct sn_rxq_registers *>(ptr);
		ptr += ROUND_TO_64(sizeof(struct sn_rxq_registers));

		/* Driver -> BESS */
		llring_init(reinterpret_cast<struct llring *>(ptr), SLOTS_PER_LLRING,
			    SINGLE_P, SINGLE_C);
		out_qs_[i].drv_to_sn = reinterpret_cast<struct llring *>(ptr);
		ptr += ROUND_TO_64(bytes_per_llring);

		/* BESS -> Driver */
		llring_init(reinterpret_cast<struct llring *>(ptr), SLOTS_PER_LLRING,
			    SINGLE_P, SINGLE_C);
		out_qs_[i].sn_to_drv = reinterpret_cast<struct llring *>(ptr);
		ptr += ROUND_TO_64(bytes_per_llring);
	}

	return bar;
}

void DyscoVPort::InitDriver() {
	struct stat buf;

	int ret;

	next_cpu = 0;

	ret = stat("/dev/bess", &buf);
	if (ret < 0) {
		char exec_path[1024];
		char *exec_dir;

		char cmd[2048];

		LOG(INFO) << "vport: BESS kernel module is not loaded. Loading...";

		ret = readlink("/proc/self/exe", exec_path, sizeof(exec_path));
		if (ret == -1 || ret >= static_cast<int>(sizeof(exec_path)))
			return;

		exec_path[ret] = '\0';
		exec_dir = dirname(exec_path);

		snprintf(cmd, sizeof(cmd), "insmod %s/kmod/bess.ko", exec_dir);
		ret = system(cmd);
		if (WEXITSTATUS(ret) != 0) {
			LOG(WARNING) << "Cannot load kernel module " << exec_dir
				     << "/kmod/bess.ko";
		}
	}
}

int DyscoVPort::SetIPAddrSingle(const std::string &ip_addr) {
	FILE *fp;

	char buf[1024];

	int ret;
	int exit_code;

	ret = snprintf(buf, sizeof(buf), "ip addr add %s dev %s 2>&1",
		       ip_addr.c_str(), ifname_);
	if (ret >= static_cast<int>(sizeof(buf)))
		return -EINVAL;

	fp = popen(buf, "r");
	if (!fp)
		return -errno;
	//Dysco
	inet_pton(AF_INET, ip_addr.c_str(), &devip);
	fprintf(stderr, "[DyscoVPort]: ip=%u(%s)\n", devip, ip_addr.c_str());
	
	ret = pclose(fp);
	exit_code = WEXITSTATUS(ret);
	if (exit_code)
		return -EINVAL;

	return 0;
}

CommandResponse DyscoVPort::SetIPAddr(const bess::pb::DyscoVPortArg &arg) {
	int child_pid = 0;

	int ret = 0;
	int nspace = 0;

	/* change network namespace if necessary */
	if (container_pid_ || netns_fd_ >= 0) {
		nspace = 1;

		child_pid = fork();
		if (child_pid < 0) {
			return CommandFailure(-child_pid);
		}

		if (child_pid == 0) {
			char buf[1024];
			int fd;

			if (container_pid_) {
				snprintf(buf, sizeof(buf), "/proc/%d/ns/net", container_pid_);
				fd = open(buf, O_RDONLY);
				if (fd < 0) {
					PLOG(ERROR) << "open(/proc/pid/ns/net)";
					_exit(errno <= 255 ? errno : ENOMSG);
				}
			} else
				fd = netns_fd_;

			ret = setns(fd, 0);
			if (ret < 0) {
				PLOG(ERROR) << "setns()";
				_exit(errno <= 255 ? errno : ENOMSG);
			}
		} else {
			goto wait_child;
		}
	}

	if (arg.ip_addrs_size() > 0) {
		for (int i = 0; i < arg.ip_addrs_size(); ++i) {
			const char *addr = arg.ip_addrs(i).c_str();
			ret = SetIPAddrSingle(addr);
			if (ret < 0) {
				if (nspace) {
					/* it must be the child */
					DCHECK_EQ(child_pid, 0);
					_exit(errno <= 255 ? errno : ENOMSG);
				} else
					break;
			}
		}
	} else {
		DCHECK(0);
	}

	if (nspace) {
		if (child_pid == 0) {
			if (ret < 0) {
				ret = -ret;
				_exit(ret <= 255 ? ret : ENOMSG);
			} else
				_exit(0);
		} else {
			int exit_status;

		wait_child:
			ret = waitpid(child_pid, &exit_status, 0);

			if (ret >= 0) {
				DCHECK_EQ(ret, child_pid);
				ret = -WEXITSTATUS(exit_status);
			} else
				PLOG(ERROR) << "waitpid()";
		}
	}

	if (ret < 0) {
		return CommandFailure(-ret,
				      "Failed to set IP addresses "
				      "(incorrect IP address format?)");
	}

	return CommandSuccess();
}

void DyscoVPort::DeInit() {
	int ret;

	ret = ioctl(fd_, SN_IOC_RELEASE_HOSTNIC);
	if (ret < 0)
		PLOG(ERROR) << "ioctl(SN_IOC_RELEASE_HOSTNIC)";

	close(fd_);
	FreeBar();
}

CommandResponse DyscoVPort::Init(const bess::pb::DyscoVPortArg &arg) {
	CommandResponse err;
	int ret;
	phys_addr_t phy_addr;

	struct tx_queue_opts txq_opts = tx_queue_opts();
	struct rx_queue_opts rxq_opts = rx_queue_opts();

	fd_ = -1;
	netns_fd_ = -1;
	container_pid_ = 0;

	if (arg.ifname().length() >= IFNAMSIZ) {
		err = CommandFailure(EINVAL,
				     "Linux interface name should be "
				     "shorter than %d characters",
				     IFNAMSIZ);
		goto fail;
	}

	if (arg.ifname().length()) {
		strncpy(ifname_, arg.ifname().c_str(), IFNAMSIZ);
	} else {
		strncpy(ifname_, name().c_str(), IFNAMSIZ);
	}

	if (arg.cpid_case() == bess::pb::DyscoVPortArg::kDocker) {
		err = docker_container_pid(arg.docker(), &container_pid_);
		if (err.error().code() != 0)
			goto fail;
	} else if (arg.cpid_case() == bess::pb::DyscoVPortArg::kContainerPid) {
		container_pid_ = arg.container_pid();
	} else if (arg.cpid_case() == bess::pb::DyscoVPortArg::kNetns) {
		netns_fd_ = open(arg.netns().c_str(), O_RDONLY);
		if (netns_fd_ < 0) {
			err = CommandFailure(EINVAL, "Invalid network namespace %s",
					     arg.netns().c_str());
			goto fail;
		}
		//Dysco
		memcpy(ns, arg.netns().c_str(), arg.netns().length());
	}

	if (arg.rxq_cpus_size() > 0 &&
	    arg.rxq_cpus_size() != num_queues[PACKET_DIR_OUT]) {
		err = CommandFailure(EINVAL, "Must specify as many cores as rxqs");
		goto fail;
	}

	fd_ = open("/dev/bess", O_RDONLY);
	if (fd_ == -1) {
		err = CommandFailure(ENODEV, "the kernel module is not loaded");
		goto fail;
	}

	txq_opts.tci = arg.tx_tci();
	txq_opts.outer_tci = arg.tx_outer_tci();
	rxq_opts.loopback = arg.loopback();

	bar_ = AllocBar(&txq_opts, &rxq_opts);
	phy_addr = rte_malloc_virt2phy(bar_);

	VLOG(1) << "virt: " << bar_ << ", phys: " << phy_addr;

	ret = ioctl(fd_, SN_IOC_CREATE_HOSTNIC, &phy_addr);
	if (ret < 0) {
		err = CommandFailure(-ret, "SN_IOC_CREATE_HOSTNIC failure");
		goto fail;
	}

	if (arg.ip_addrs_size() > 0) {
		err = SetIPAddr(arg);

		if (err.error().code() != 0) {
			DeInit();
			goto fail;
		}
	}

	if (netns_fd_ >= 0) {
		close(netns_fd_);
		netns_fd_ = -1;
	}

	for (int cpu = 0; cpu < SN_MAX_CPU; cpu++) {
		map_.cpu_to_txq[cpu] = cpu % num_queues[PACKET_DIR_INC];
	}

	if (arg.rxq_cpus_size() > 0) {
		for (int rxq = 0; rxq < num_queues[PACKET_DIR_OUT]; rxq++) {
			map_.rxq_to_cpu[rxq] = arg.rxq_cpus(rxq);
		}
	} else {
		for (int rxq = 0; rxq < num_queues[PACKET_DIR_OUT]; rxq++) {
			next_cpu = find_next_nonworker_cpu(next_cpu);
			map_.rxq_to_cpu[rxq] = next_cpu;
		}
	}

	ret = ioctl(fd_, SN_IOC_SET_QUEUE_MAPPING, &map_);
	if (ret < 0) {
		PLOG(ERROR) << "ioctl(SN_IOC_SET_QUEUE_MAPPING)";
	}

	return CommandSuccess();

 fail:
	if (fd_ >= 0)
		close(fd_);

	if (netns_fd_ >= 0)
		close(netns_fd_);

	return err;
}

int DyscoVPort::RecvPackets(queue_t qid, bess::Packet **pkts, int max_cnt) {
	struct queue *tx_queue = &inc_qs_[qid];
	phys_addr_t paddr[bess::PacketBatch::kMaxBurst];
	int cnt;
	int i;

	if (static_cast<size_t>(max_cnt) > bess::PacketBatch::kMaxBurst) {
		max_cnt = bess::PacketBatch::kMaxBurst;
	}
	cnt = llring_sc_dequeue_burst(tx_queue->drv_to_sn, paddr, max_cnt);

	refill_tx_bufs(tx_queue->sn_to_drv);

	for (i = 0; i < cnt; i++) {
		bess::Packet *pkt;
		struct sn_tx_desc *tx_desc;
		uint16_t len;

		pkt = pkts[i] = bess::Packet::from_paddr(paddr[i]);

		tx_desc = pkt->scratchpad<struct sn_tx_desc *>();
		len = tx_desc->total_len;

		pkt->set_data_off(SNBUF_HEADROOM);
		pkt->set_total_len(len);
		pkt->set_data_len(len);

		/* TODO: process sn_tx_metadata */
	}

	return cnt;
}

int DyscoVPort::SendPackets(queue_t qid, bess::Packet **pkts, int cnt) {
	struct queue *rx_queue = &out_qs_[qid];

	phys_addr_t paddr[bess::PacketBatch::kMaxBurst];

	int ret;

	assert(static_cast<size_t>(cnt) <= bess::PacketBatch::kMaxBurst);

	reclaim_packets(rx_queue->drv_to_sn);

	for (int i = 0; i < cnt; i++) {
		bess::Packet *snb = pkts[i];

		struct sn_rx_desc *rx_desc;

		rx_desc = snb->scratchpad<struct sn_rx_desc *>();

		rte_prefetch0(rx_desc);

		paddr[i] = snb->paddr();
	}

	for (int i = 0; i < cnt; i++) {
		bess::Packet *snb = pkts[i];
		bess::Packet *seg;

		struct sn_rx_desc *rx_desc;

		rx_desc = snb->scratchpad<struct sn_rx_desc *>();

		rx_desc->total_len = snb->total_len();
		rx_desc->seg_len = snb->head_len();
		rx_desc->seg = snb->dma_addr();
		rx_desc->next = 0;

		rx_desc->meta = sn_rx_metadata();

		seg = reinterpret_cast<bess::Packet *>(snb->next());
		while (seg) {
			struct sn_rx_desc *next_desc;
			bess::Packet *seg_snb;

			seg_snb = (bess::Packet *)seg;
			next_desc = seg_snb->scratchpad<struct sn_rx_desc *>();

			next_desc->seg_len = seg->head_len();
			next_desc->seg = seg->dma_addr();
			next_desc->next = 0;

			rx_desc->next = seg_snb->paddr();
			rx_desc = next_desc;
			seg = reinterpret_cast<bess::Packet *>(snb->next());
		}
	}

	ret = llring_mp_enqueue_bulk(rx_queue->sn_to_drv, paddr, cnt);

	if (ret == -LLRING_ERR_NOBUF)
		return 0;

	/* TODO: generic notification architecture */
	if (__sync_bool_compare_and_swap(&rx_queue->rx_regs->irq_disabled, 0, 1)) {
		ret = ioctl(fd_, SN_IOC_KICK_RX, 1 << map_.rxq_to_cpu[qid]);
		if (ret) {
			PLOG(ERROR) << "ioctl(KICK_RX)";
		}
	}

	return cnt;
}

ADD_DRIVER(DyscoVPort, "dysco_vport", "Dysco virtual port for Linux host")
