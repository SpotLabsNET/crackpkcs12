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

#define DEFAULTMSGINTERVAL 100000
#define DEFAULTMINWORDLENGTH 1
#define DEFAULTMAXWORDLENGTH 8
#define MINWORDLENGTH 1
#define MAXWORDLENGTH 2048
#define MINARGNUMBER 4
#define PARTIALBASESIZE 256
#define MAXBASESIZE 1024

typedef struct {
	int id;
	int num_threads;
	FILE* dictfile;
	char *file2crack;
	pthread_mutex_t *m;
	pthread_mutexattr_t *m_attr;
	int msginterval;
} workerdict;

typedef struct {
	int id;
	int num_threads;
	char *base;
	int baselength;
	int wordlength_min;
	int wordlength;
	char *word;
	char *file2crack;
	pthread_mutex_t *m;
	pthread_mutexattr_t *m_attr;
	int msginterval;
} workerbrute;

void usage() {
	printf(
"\nUsage:\n\ncrackpkcs12 { -d <dictionary_file> |  -b [ -m <min_psw_length> ] [ -M <max_psw_length> ] [ -c <base_char_sets> ] } [ -t <num_of_threads> ] [ -v ] [ -s <message_interval> ] <file_to_crack>\n"
"\n"
"  -b                       Uses brute force attack\n\n"
"  -m <min_password_length> Specifies minimum length of password (implies -b)\n\n"
"  -M <max_password_length> Specifies minimum length of password (implies -b)\n\n"
"  -c <base_char_sets>      Specifies characters sets (one or more than one) and order to conform passwords (requires -b, -m or -M)\n"
"                           a = letters (abcdefghijklmnopqrstuvwxyz)\n"
"                           A = capital letters (ABCDEFGHIJKLMNOPQRSTUVWXYZ)\n"
"                           n = digits (0123456789)\n"
"                           s = special characters (!\"#$%%&'()*+,-./:;<=>?@[\\]^_`{|}~)\n"
"                           x = all previous sets\n\n"
"  -d <dictionary_file>     Uses dictionary attack and specify dictionary file path\n\n"
"  -t <number_of_threads>   Specifies number of threads (by default number of CPU's)\n\n"
"  -v                       Verbose mode\n\n"
"  -s <message_inteval>     Number of attemps between messages (implied -v) (default 100000)\n\n"
	);
	exit(100);
}

char* getbase(char *scs);
void *work_dict(void *ptr);
void *work_brute(void *ptr);
void generate(workerbrute *wthread, int pivot, PKCS12 *p12, long long *gcount);
void try(workerbrute *wthread, PKCS12 *p12, long long *gcount);

int main(int argc, char** argv) {

	char *psw, *infile, *dict, *nt, *msgintstring, verbose, isdict, isbrute, *swl_min, *swl_max, *scs, *base;
	int c;
	int msginterval = DEFAULTMSGINTERVAL;
	int wordlength_min = MINWORDLENGTH;
	int wordlength_max = 0;
	verbose = 0;
	psw = NULL;
	infile = NULL;
	dict = NULL;
	nt = NULL;
	msgintstring = NULL;
	scs = NULL;
	nt = NULL;
	isdict = 0;
	isbrute = 0;
	swl_min = NULL;
	swl_max = NULL;
	base = NULL;
	int nthreads = sysconf (_SC_NPROCESSORS_ONLN);

	while ((c = getopt (argc, argv, "t:d:vbm:M:c:s:")) != -1)
		switch (c) {
			case 'b':
				isbrute = 1;
				break;
			case 'M':
				isbrute = 1;
				swl_max = optarg;				
				break;
			case 'm':
				isbrute = 1;
				swl_min = optarg;				
				break;
			case 'c':
				scs = optarg;				
				break;
			case 'd':
				isdict = 1;
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

	if (!isdict && !isbrute) {
		fprintf(stderr,"Error: Choose at least one attack type (-d for dictionary attack or -b for brute force attack)\n\n");
		usage();
	}

	if (optind != argc-1)
		usage();
	else
		infile = argv[optind];

	if (isdict == 1 && dict == NULL) {
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

	if (swl_min != NULL) {
		wordlength_min = strtol(swl_min, NULL, 10);
		if (errno == EINVAL)
			usage();
		if (wordlength_min < MINWORDLENGTH) {
			wordlength_min = MINWORDLENGTH;
			printf("\nForcing min word length to %d\n\n",wordlength_min);
		}
	}
	else
	    wordlength_min = DEFAULTMINWORDLENGTH;

	if (swl_max != NULL) {
		wordlength_max = strtol(swl_max, NULL, 10);
		if (errno == EINVAL)
			usage();
		if (wordlength_max > MAXWORDLENGTH) {
			wordlength_max = MAXWORDLENGTH;
			printf("\nForcing max word length to %d\n\n",wordlength_max);
		}
	}
	else
	    wordlength_max = DEFAULTMAXWORDLENGTH;

	if (wordlength_min > wordlength_max) {
		if (swl_min != NULL && swl_max != NULL) {
			fprintf(stderr,"Error: Min length is greater than max length\n\n");
			usage();
		}
		else if (swl_min != NULL && swl_max == NULL)
			wordlength_max = wordlength_min;
		else if (swl_min == NULL && swl_max != NULL)
			wordlength_min = wordlength_max;
	}

	if (isbrute) {
		if (scs == NULL)
			scs = "x"; // by default all character sets
		base = getbase(scs);
		if (base == NULL)
			usage();
	}
	else if (scs != NULL) {
		printf("-c option requires -b option\n");
		usage();
	}

	if (nt != NULL) {
		nthreads = strtol(nt, NULL, 10);
		if (errno == EINVAL)
			usage();
		if (verbose)
			printf("\nStarting %d threads\n\n",nthreads);
	}

	OpenSSL_add_all_algorithms();

	pthread_t *thread = (pthread_t *) calloc(nthreads,sizeof(pthread_t));
	int *thread_ret = (int *) calloc(nthreads, sizeof(int));
	pthread_mutex_t mutex;
	pthread_mutexattr_t mutex_attr;
	pthread_mutex_init(&mutex,&mutex_attr);
	int i;
	if (isdict) {
		// Opening dictionary file
		FILE *dictfile = fopen(dict,"r");
		if (!dictfile) {
			fprintf(stderr,"Dictionary file not found: %s\n",dict);
			exit(20);
		}
		workerdict *wthread = (workerdict *) calloc(nthreads,sizeof(workerdict));
	
		printf("\nDictionary attack - Starting %d threads\n\n",nthreads);

		for (i=0; i<nthreads; i++) {
			wthread[i].id = i;
			wthread[i].num_threads = nthreads;
			wthread[i].m = &mutex;
			wthread[i].m_attr = &mutex_attr;
			wthread[i].dictfile = dictfile;
			wthread[i].file2crack = infile;
			if (verbose == 1) wthread[i].msginterval = msginterval;
			thread_ret[i] = pthread_create( &thread[i], NULL, work_dict, (void*) &wthread[i]);
		}
		for (i=0; i<nthreads; i++) {
			pthread_join(thread[i], NULL);
			printf("\nDictionary attack - Exhausted search\n");
		}
	}
	
	if (isbrute) {
		workerbrute *wthread = (workerbrute *) calloc(nthreads,sizeof(workerbrute));

		printf("\nBrute force attack - Starting %d threads\n",nthreads);
		printf("\nMin length: %d\nMax length: %d\nUse -m and -M flags to modify these values.\n\n", wordlength_min, wordlength_max);
	
		for (i=0; i<nthreads; i++) {
			wthread[i].id = i;
			wthread[i].num_threads = nthreads;
			wthread[i].wordlength_min = wordlength_min;
			wthread[i].wordlength = wordlength_max;
			wthread[i].word = (char *) calloc(wordlength_max, sizeof(char));
			wthread[i].base = base;
			wthread[i].baselength = strlen(base);
			wthread[i].m = &mutex;
			wthread[i].m_attr = &mutex_attr;
			wthread[i].file2crack = infile;
			if (verbose == 1) wthread[i].msginterval = msginterval;
			thread_ret[i] = pthread_create( &thread[i], NULL, work_brute, (void*) &wthread[i]);
		}
		for (i=0; i<nthreads; i++)
			pthread_join(thread[i], NULL);

		printf("\nBrute force attack - Exhausted search\n");
	}

	printf("\nNo password found\n\n");

	pthread_exit(NULL);
	exit(0);
}

char* getbase(char *scs) {
	char alpha[PARTIALBASESIZE] = "abcdefghijklmnopqrstuvwxyz";
	char special[PARTIALBASESIZE] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	char capital[PARTIALBASESIZE] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char numeric[PARTIALBASESIZE] = "0123456789";
	char isa = 0;
	char isA = 0;
	char isn = 0;
	char iss = 0;

	char *base = (char *)calloc(MAXBASESIZE,sizeof(char));

	int i;
	for (i=0; i<strlen(scs); i++) {
		if (scs[i] == 'a' && isa == 0) {
			strncat(base,alpha,PARTIALBASESIZE);
			isa = 1;
		}
		else if (scs[i] == 'A' && isA == 0) {
			strncat(base,capital,PARTIALBASESIZE);
			isA = 1;
		}
		else if (scs[i] == 'n' && isn == 0) {
			strncat(base,numeric,PARTIALBASESIZE);
			isn = 1;
		}
		else if (scs[i] == 's' && iss == 0) {
			strncat(base,special,PARTIALBASESIZE);
			iss = 1;
		}
		else if (scs[i] == 'x') {
			bzero(base,MAXBASESIZE * sizeof(char));
			strncat(base,alpha,PARTIALBASESIZE);
			strncat(base,capital,PARTIALBASESIZE);
			strncat(base,numeric,PARTIALBASESIZE);
			strncat(base,special,PARTIALBASESIZE);
			return base;
		}
		else
			return NULL;
	}

	return base;
}

void *work_dict( void *ptr ) {
	// Opening p12 file
	BIO* in = NULL;
	workerdict *wthread = (workerdict *) ptr;

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

	char line[256];
	char found = 0;
	char stop = 0;
	int count = wthread->msginterval;
	int i = 0;
	char *p;
	long long gcount = wthread->msginterval-1;

	// Work
	while (!found && fgets(line, sizeof line,wthread->dictfile) != NULL) {
		p = line + strlen(line) - 1;
		if (*p == '\n') *p = '\0';
		if ((p != line) && (*--p == '\r')) *p = '\0';
		gcount++;
		if ( wthread->msginterval > 0 ) {
			if (--count <= 0) {
				printf("Dictionary attack - Thread %d - Attemp %lld (%s)\n",wthread->id+1,gcount,line);
				count = wthread->msginterval;
			}
		}
		if (PKCS12_verify_mac(p12, line, -1))
			found = 1;	
	}

	if (found) {
		printf("*********************************************************\n");
		printf("Dictionary attack - Thread %d - Password found: %s\n",wthread->id+1,line);
		printf("*********************************************************\n\n");
		exit(0);
	} else if (wthread->msginterval > 0)
		printf("Dictionary attack - Thread %d - Exhausted search (%lld attemps)\n",wthread->id+1,gcount);

	pthread_exit(0);
}

void *work_brute( void *ptr ) {
	// Opening p12 file
	BIO* in = NULL;
	workerbrute *wthread = (workerbrute *) ptr;

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

	int maxwordlength = wthread->wordlength;
	int i;
	long long gcount = 0;
	for (wthread->wordlength=wthread->wordlength_min; wthread->wordlength <= maxwordlength; wthread->wordlength++) {
		printf("Brute force attack - Thread %d - Starting with %d characters passwords\n",wthread->id+1,wthread->wordlength);
		for (i=wthread->id; i<wthread->baselength; i+=wthread->num_threads) {
			wthread->word[0] = wthread->base[i];
			if (wthread->wordlength>1)
				generate(wthread, 1, p12, &gcount);
			else
				try(wthread,p12,&gcount);
		}
	}
}

void generate(workerbrute *wthread, int pivot, PKCS12 *p12, long long *gcount) {
	int i, j, ret;

	for (i=0; i<wthread->baselength; i++) {
		wthread->word[pivot] = wthread->base[i];
		if (pivot < wthread->wordlength-1)
			generate(wthread, pivot+1, p12, gcount);
		else
			try(wthread,p12,gcount);
	}
	wthread->word[pivot] = '\0';
}

void try(workerbrute *wthread, PKCS12 *p12, long long *gcount) {
	if (wthread->msginterval) {
		(*gcount)++;
		if ((*gcount) % wthread->msginterval == 0) {
			printf("Brute force attack - Thread %d - Attemp %lld (%s)\n",wthread->id+1,(*gcount),wthread->word);
		}
	}
	if (PKCS12_verify_mac(p12, wthread->word, -1)) {
		printf("**********************************************************\n");
		printf("Brute force attack - Thread %d - Password found: %s\n",wthread->id+1,wthread->word);
		printf("**********************************************************\n\n");
		exit(0);
	}
}
