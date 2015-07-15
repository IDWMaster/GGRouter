#include <GGRouter.h>
#include <thread>
#include <unistd.h>
using namespace GGClient;


int main(int argc, char** argv) {
GlobalGridConnectionManager mngr;
mngr.CreatePortMapping_Raw(3800,[&](BStream& data){
  GLOBALGRID_PACKET packet = mngr.DecodePacket(data);
  printf("%s\n",(char*)data.buffer);
});
std::thread mtr([=](){
  char mander[256];
  int val = read(0,mander,256);
  mngr.Send(mander,val,argv[1]);
});
mngr.router.RunLoop();
return 0;
}
