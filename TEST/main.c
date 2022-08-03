#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define BUF_SIZE    (100)

int main(int argc, char **argv)
{	
	int i;
	char tmp[BUF_SIZE];
	pid_t pid = getpid();
	
    strncpy(tmp, argv[0], BUF_SIZE);
	while (strcmp(argv[0], tmp) == 0)
	{
		printf("PID: %d\n", pid);
		for (i = 0; i < argc; i++)
			printf("args: %s-%p\n", argv[i], argv[i]);
		sleep(1);
	}
    
	printf("You're allowed to enter!\n");
	return 0;
}
