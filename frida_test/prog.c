#include <stdio.h>
#include <string.h>

int main() {

	char my_str[200];
	fgets(my_str, 200, stdin);
	char buf[6];
	strncpy(buf, my_str, 200);
	return 0;
}
