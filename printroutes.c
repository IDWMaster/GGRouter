//Small utility to print IP routing table from stdin; useful for debugging

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

int main(int argc, char** argv) {

uint32_t len;
read(STDIN_FILENO,&len,4);
size_t count = len;
size_t i;
for(i = 0;i<count;i++) {
uint64_t val;
read(STDIN_FILENO,&val,8);
//printf("%i.%i.%i.%i:%i\n",(int)(unsigned char)(val),(int)(unsigned char)(val << 8),(int)(unsigned char)(val << 16),(int)(unsigned char)(val << 24),(int)(val << 32));
printf("%i\n",(int)(val << 32));
}

return 0;
}
