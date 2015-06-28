#include <OpenAuth.h>
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <string>
#include <iostream>
#include "GGRouter.h"
#include <stdio.h>
#include <stdlib.h>

using namespace GlobalGrid;


class BStream {
public:
  unsigned char* buffer;
  size_t len;
  BStream(void* buffer, size_t len) {
    this->buffer = buffer;
    this->len = len;
  }
  void Read(void* output, size_t len) {
    if(len>this->len) {
      throw "sideways";
    }
    this->len-=len;
    memcpy(output,buffer,len);
    buffer+=len;
  }
  template<typename T>
  T& Read(T& output) {
    Read(&output,sizeof(output));
    return output;
  }
  char* ReadString() {
    char* retval = (char*)buffer;
    char mander;
    while(Read(mander) != 0) {}
    return retval;
  }
  void* Increment(size_t len) {
    if(len>this->len) {
      throw "down";
    }
    void* retval = buffer;
    this->len-=len;
    this->buffer+=len;
    return retval;
  }
};

static void* dns;

static std::shared_ptr<P2PConnectionManager> mngr;
char* internet;
char* auth;
static void client_receivemsg(void* thisptr, void* data, size_t len) {
  
}
class CallOnDestroy {
public:
  std::function<void()> functor;
  CallOnDestroy(std::function<void()> functor) {
    this->functor = functor;
  }
  ~CallOnDestroy() {
    functor();
  }
};
static char* READ_STRING(SafeBuffer& buffy) {
  char* retval = (char*)buffy.ptr;
  char mander = 1;
  while(mander != 0) {
    buffy.Read(mander);
  }
  return retval;
}
typedef struct {
  void* channel;
  uint32_t callback_channel;
} GLOBALGRID_PORT_MAPPING;
static inline void XorBlock(uint64_t* current, const uint64_t* prev) {
  current[0] ^=prev[0];
  current[1] ^=prev[1]; 
}
static void gg_port_destroy(void* thisptr) {
  delete (GLOBALGRID_PORT_MAPPING*)thisptr;
}
static void gg_recv(void* thisptr, unsigned char* src, int32_t srcPort, unsigned char* data, size_t sz) {
  GLOBALGRID_PORT_MAPPING* mapping = (GLOBALGRID_PORT_MAPPING*)thisptr;
  unsigned char* response = new unsigned char[4+4+sz];
  memcpy(response,&mapping->callback_channel,4);
  memcpy(response+4,&srcPort,4);
  memcpy(response+4+4,data,sz);
  delete[] response;
}
static void server_receivemsg(void* thisptr, void* channel, void* _data, size_t len) {
 //SubmitWork function
  
       void* data = malloc(len);
       SubmitWork([=](){
	 CallOnDestroy cd([=](){
	   free(data);
	});
	 try {
  BStream buffer((unsigned char*)data,len);
 unsigned char mander;
 buffer.Read(mander);
 uint32_t callback_channel;
 buffer.Read(callback_channel);
   switch(mander) {
     case 0:
     {
       //Get GUID
       unsigned char* response = new unsigned char[4+16];
       memcpy(response,&callback_channel,4);
       mngr->getID(response+4);
       Platform_Channel_Transmit(channel,response,4+16);
       delete[] response;
     }
     break;
     case 1:
       //Transmit packet (RAW) -- IMPORTANT NOTE, PACKET SIZE MUST BE DIVISIBLE BY 16 bytes
     {
       char* dest = buffer.ReadString();
       uint32_t port;
       buffer.Read(port);
       uint32_t len;
       buffer.Read(len);
       unsigned char* data = (unsigned char*)buffer.Increment(len);
       unsigned char gaddr[16];
       unsigned char key[32];
       unsigned char* response = new unsigned char[4+1];
       memcpy(response,&len,4);
       if(GGDNS_ResolveHost(auth,dest,gaddr,key)) {
	 //Encrypt
	 AES_Encrypt(key,data);
	 for(size_t i = 16;i<len;i+=16) {
	   XorBlock(data+i,data+i-16);
	   AES_Encrypt(key,data+i);
	 }
	 GlobalGrid_Send(mngr->nativePtr,dest,callback_channel,port,data,len);
	  
	 *(response+4) = 1;
       }else {
	 //Host resolution failure
	 *(response+4) = 0;
       }
       Platform_Channel_Transmit(channel,response,4+1);
       delete[] response;
     }
       break;
     case 2:
       //Open port
       uint32_t portno;
       buffer.Read(portno);
       ReceiveCallback cb;
       cb.onDestroyed = 0;
       cb.onReceived = gg_recv;
       cb.onDestroyed = gg_port_destroy;
       GlobalGrid_OpenPort(mngr->nativePtr,portno,cb);
       break;
  }
}catch(const char* er) {
 }
      });
  
}

int main(int argc, char** argv) {

  
  if(argv[1] == std::string("connect")) {
    //Connect
    void* connection = Platform_Channel_Connect(argv[2]);
    Platform_Channel_Transmit(connection,(void*)"world",6);
    sleep(-1);
    
  }else {
    if(argv[1] == std::string("demon")) {
      
      std::shared_ptr<P2PConnectionManager> mngr = std::make_shared<P2PConnectionManager>();
      InternetProtocol ip(3701,mngr);
      mngr->RegisterProtocol(&ip);
      dns = GGDNS_Init(mngr->nativePtr);
      ::mngr = mngr;
      internet = argv[2];
      //Angels and Daemons!
      void* server = Platform_Open_Named_Channel(argv[2]);
      while(true) {
	Platform_Channel_ReadMsg(server,0,server_receivemsg);
      }
    }
  }
  
return 0;
}
