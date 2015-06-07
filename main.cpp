#include <OpenAuth.h>
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <string>
#include <iostream>
#include "GGRouter.h"
#include <stdio.h>
#include <stdlib.h>

using namespace GlobalGrid;



static void server_receivemsg(void* thisptr, void* channel, void* data, size_t len) {
  std::cout<<(const char*)data<<std::endl;
}

int main(int argc, char** argv) {

  
  if(argv[1] == std::string("connect")) {
    //Connect
    void* connection = Platform_Channel_Connect(argv[2]);
    Platform_Channel_Transmit(connection,(void*)"world",6);
    sleep(-1);
    
  }else {
    if(argv[1] == std::string("demon")) {
      //Angels and Daemons!
      void* server = Platform_Open_Named_Channel(argv[2]);
      while(true) {
	Platform_Channel_ReadMsg(server,0,server_receivemsg);
      }
    }
  }
  
std::shared_ptr<P2PConnectionManager> mngr = std::make_shared<P2PConnectionManager>();
GGDNS_Init(mngr->nativePtr);
  
return 0;
}
