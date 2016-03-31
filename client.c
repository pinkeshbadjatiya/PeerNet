#include "all_headers.h"

int main(int argc, char *argv[]) {
	if (verify_directory() == -1 ) {
		exit(EXIT_FAILURE);
	};
	if (argc < 3) {
		fprintf(stderr,"usage %s hostname port\n", argv[0]);
		exit(0);
	}

	chdir(shared_dir);
	compile_regexes();

	//////////////////////////////////////////////////////////////

	THREAD_DATA *CLIENT_FOUND = NULL;
	CLIENT_FOUND = (THREAD_DATA*)malloc(sizeof(THREAD_DATA));
	strcpy(CLIENT_FOUND->ip, argv[1]);
	CLIENT_FOUND->port = atoi(argv[2]);

	client_main(CLIENT_FOUND);

	return 0;
}
