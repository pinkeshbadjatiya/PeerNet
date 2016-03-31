#include "all_headers.h"

int main(int argc, char *argv[]) {
	if (verify_directory() == -1 ) {
		exit(EXIT_FAILURE);
	};
	if (argc!=1 && argc!=3) {
		fprintf(stderr,"ERROR, no ip provided\n");
		fprintf(stderr, "USAGE: %s [CLIENT_ADDRESS] [PORTNO]\n",argv[0]);
		exit(1);
	}
	if (argc == 3) {
		CLIENT_FOUND = (THREAD_DATA*)malloc(sizeof(THREAD_DATA));
		strcpy(CLIENT_FOUND->ip, argv[1]);
		CLIENT_FOUND->port = atoi(argv[2]);
	}
	chdir(shared_dir);
	compile_regexes();

	//////////////////////////////////////////////////////////////

	pthread_t threads[MAX_THREADS];

	Pthread_create(&threads[0], NULL, server_main, NULL);	// Server thread
	while(CLIENT_FOUND == NULL) {}
	Pthread_create(&threads[1], NULL, client_main, CLIENT_FOUND);	// Client thread

	// First wait for client to end
	Pthread_join(threads[1], NULL);
	Pthread_join(threads[0], NULL);
	return 0;
}
