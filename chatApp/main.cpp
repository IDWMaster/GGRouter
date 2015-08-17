#include "../GGRouter.h"
#include <thread>
#include <unistd.h>
#include <fcntl.h>
using namespace GGClient;


int main(int argc, char** argv) {
printf("Connecting to GlobalGrid connection manager....");
  GlobalGridConnectionManager mngr("main");
if(mngr.router.channel == 0) {
  printf("Error occured connecting to GlobalGrid demon. Please ensure the main instance is running.\n");
  return -1;
}
mngr.router.RunLoop();
return 0;
}
