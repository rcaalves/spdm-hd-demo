#include<sys/time.h>
#include<time.h>
#include<stdio.h>
#include<stdlib.h>

enum argvnum {SRC_DIR=1, DST_DIR, IN_FILE, ITER};

int main(int argc,char** argv)
{
	if(argc<4)
	{
		printf("Usage: %s [src dir] [dst dir] [input file] [iterations] \n", argv[0]);
		return 0;
	}
	FILE* inputs = fopen(argv[IN_FILE], "r");
	if(!inputs)
	{
		printf("Failed to open file %s\n", argv[IN_FILE]);
		return 0;
	}
	struct timeval start, end;
	int iterations = atoi (argv[ITER]);
	char *line = NULL;
	size_t len;
	ssize_t read;

	char outfile[0x100];

	time_t t;
	time(&t);
	struct tm mytm;
	localtime_r(&t, &mytm);

	// struct tm {
	//     int tm_sec;    /* Seconds (0-60) */
	//     int tm_min;    /* Minutes (0-59) */
	//     int tm_hour;   /* Hours (0-23) */
	//     int tm_mday;   /* Day of the month (1-31) */
	//     int tm_mon;    /* Month (0-11) */
	//     int tm_year;   /* Year - 1900 */
	//     int tm_wday;   /* Day of the week (0-6, Sunday = 0) */
	//     int tm_yday;   /* Day in the year (0-365, 1 Jan = 0) */
	//     int tm_isdst;  /* Daylight saving time */
	// };

	sprintf(outfile, "copytest%d%02d%02d%02d%02d%02d.copytime", mytm.tm_year + 1900, mytm.tm_mon+1, mytm.tm_mday, mytm.tm_hour, mytm.tm_min, mytm.tm_sec);
	FILE* output = fopen(outfile, "w");
	printf("%s\n", outfile);

	while ((read = getline(&line, &len, inputs)) != -1)
	{
		char cp_cmd[0x1000];
		char rm_cmd[0x1000];
		char aux_str[0x1000];
		const char clear_cache_cmd[] = "sync; echo 3 > /proc/sys/vm/drop_caches";
		// fputs(line, output);
		line[read-1]='\0';

		sprintf(cp_cmd, "cp %s/%s %s", argv[SRC_DIR], line, argv[DST_DIR]);
		sprintf(rm_cmd, "rm -f %s/%s", argv[DST_DIR], line);

		printf("Testing \"%s\"\n", cp_cmd);
		fputs(cp_cmd, output);
		fputs("\n", output);

		sprintf (aux_str, "%s/%s", argv[DST_DIR], line);
		FILE* exist_test = fopen(aux_str, "r");
		if(!exist_test)
		{
			int i;
			for(i = 0; i < iterations; ++i)
			{
				system(clear_cache_cmd);
				printf("\titeration %d/%d\n", i+1, iterations);
				gettimeofday (&start, NULL);
				system(cp_cmd);
				system(clear_cache_cmd);
				gettimeofday(&end, NULL);
				system(rm_cmd);

				long secs, usecs;
				secs = end.tv_sec - start.tv_sec;
				usecs = (secs*1000000 + end.tv_usec - start.tv_usec);
				sprintf(aux_str, "%ld\n", usecs);
				fputs(aux_str, output);
			}
		} else {
			fclose(exist_test);
			printf("\tFile %s exists, skipping test\n", aux_str);
			printf("\tPress enter to continue\n");
			getchar();
		}
	}
	fclose(output);
	fclose(inputs);
	free(line);
	return 0;
}