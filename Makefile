all:
	gcc dysco_ctl.c -o dysco_ctl
	gcc dysco_ctl_sender.c -o dysco_ctl_sender
	gcc heart-cli.c -o cli
	gcc heart-srv.c -o srv
