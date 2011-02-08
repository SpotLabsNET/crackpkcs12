/* This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>

#define DEFAULTMSGINTERVAL 10000;
#define MINARGNUMBER 4

typedef struct {
	int id;
	int num_threads;
	char *dict_path;
	char *file2crack;
	pthread_mutex_t *m;
	pthread_mutexattr_t *m_attr;
	int msginterval;
} worker;

void usage() {
	printf(
"\nUsage: crackpkcs12 -d <dictionary_file> [ -t <number_of_threads> ] [ -v [ -s <message_interval> ] ] <file_to_crack>\n"
"\n"
"  -d <dictionary_file>     Specify dictionary file path\n"
"  -t <number_of_threads>   Specify number of threads (by default number of CPU's)\n"
"  -v                       Verbose mode\n"
"  -s <message_inteval>     Number of attemps between messages (implied -v)\n\n"
	);
	exit(100);
}

void *work( void *ptr );

int main(int argc, char** argv) {

	if (argc < MINARGNUMBER) usage();

	char *psw, *infile, *dict, *nt, *msgintstring, c, verbose;
	int msginterval = DEFAULTMSGINTERVAL;    
	verbose = 0;
	msgintstring = NULL;
	nt = NULL;
	dict = NULL;
	infile = NULL;
	int nthreads = sysconf (_SC_NPROCESSORS_ONLN);

	while ((c = getopt (argc, argv, "t:d:vs:")) != -1)
		switch (c) {
			case 'd':
				dict = optarg;
				break;
			case 't':
				nt = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case 's':
				verbose = 1;
				msgintstring = optarg;
				break;
			case '?':
				if (optopt == 't' || optopt == 'd' || optopt == 's') {
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				}
			default:
				usage();
		}

	if (optind != argc-1)
		usage();
	else
		infile = argv[optind];

	if (dict == NULL) {
		fprintf(stderr,"Error: No dictionary file specified\n\n");
		usage();
	}

	if (msgintstring != NULL) {
		msginterval = strtol(msgintstring, NULL, 10);
		if (errno == EINVAL)
			usage();
	}
	else if (verbose == 1)
		msginterval = DEFAULTMSGINTERVAL;

	if (nt != NULL) {
		nthreads = strtol(nt, NULL, 10);
		if (errno == EINVAL)
			usage();
		if (verbose)
			printf("\nStarting %d threads\n\n",nthreads);
	}
	else if (verbose)
		printf("\nStarting %d threads (default value = number of CPU's)\n\n",nthreads);
	
	OpenSSL_add_all_algorithms();

	pthread_t *thread = (pthread_t *) calloc(nthreads,sizeof(pthread_t));    
	int *thread_ret = (int *) calloc(nthreads, sizeof(int));    
	worker *wthread = (worker *) calloc(nthreads,sizeof(worker));
	pthread_mutex_t mutex;
	pthread_mutexattr_t mutex_attr;
	pthread_mutex_init(&mutex,&mutex_attr);
	int i;
	for (i=0; i<nthreads; i++) {
		wthread[i].id = i;
		wthread[i].num_threads = nthreads;
		wthread[i].dict_path = dict;
		wthread[i].file2crack = infile;
		wthread[i].m = &mutex;
		wthread[i].m_attr = &mutex_attr;
		if (verbose == 1) wthread[i].msginterval = msginterval;
		thread_ret[i] = pthread_create( &thread[i], NULL, work, (void*) &wthread[i]);
	}

	for (i=0; i<nthreads; i++)
		pthread_join(thread[i], NULL);

	printf("\nNo password found\n\n");

	pthread_exit(NULL);
	exit(0);
}

void *work( void *ptr ) {
	// Opening p12 file    
	BIO* in = NULL;
	worker *wthread = (worker *) ptr;

	pthread_mutex_lock(wthread->m);    

	in = BIO_new_file(wthread->file2crack, "rb");
	if (!in) {
		fprintf (stderr,"PKCS12 file not found: %s\n",wthread->file2crack);
		exit(10);
	}

	// Creating PKCS12 object
	PKCS12 *p12 = NULL;
	if (!(p12 = d2i_PKCS12_bio (in, NULL))) {
		perror("Unable to create PKCS12 object\n");
		exit(30);        
	}

	pthread_mutex_unlock(wthread->m);    

	// Opening dictionary file
	FILE *file = fopen(wthread->dict_path,"r");
	if (!file) {
		fprintf(stderr,"Dictionary file not found: %s\n",wthread->dict_path);
		exit(20);
	}

	char line[256];
	char found = 0;
	char stop = 0;
	int count = 0;
	int i = 0;

	// Read first lines    
	for (i=0; i<wthread->id && stop==0; i++)
		if (fgets ( line, sizeof line, file ) == NULL) stop=1;

	// Work
	if (stop == 0) {
		while (1) {    
			if (fgets ( line, sizeof line, file ) != NULL) {
				if (line[strlen(line) - 1] == '\n')
					line[strlen(line) - 1] = '\0';
				if (strlen(line) > 0 && line[strlen(line) - 1] == '\r')
					line[strlen(line) - 1] = '\0';		
				if ( wthread->msginterval > 0 ) {
					count++;
					if (count % wthread->msginterval == 0)
						printf("Thread %d - Attemp %d (%s)\n",wthread->id+1,count,line);
				}
				if (PKCS12_verify_mac(p12, line, -1)) {
					found = 1;            
					break;
				}
			} else
				break;
			for (i=0; i<wthread->num_threads-1 && stop==0; i++)
				if (fgets ( line, sizeof line, file ) == NULL)
					stop=1;
			if (stop == 1)
				break;
		}
	}

	if (found) {
		if (wthread->msginterval > 0) printf("\n********************************************\n");        
		printf("Thread %d - Password found: %s\n",wthread->id+1,line);
		if (wthread->msginterval > 0) printf("********************************************\n\n");       
		exit(0);
	} else if (wthread->msginterval > 0)
		printf("Thread %d - Exhausted search (%d attemps)\n",wthread->id+1,count);

	pthread_exit(0);
}
