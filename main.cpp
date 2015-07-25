#include <OpenAuth.h>
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <string>
#include <iostream>
#include "GGRouter.h"
#include <stdio.h>
#include <stdlib.h>
#include "sqlite3.h"
using namespace GlobalGrid;



static void* dns;

static std::shared_ptr<P2PConnectionManager> mngr;
static char* auth;
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
typedef struct {
  void* channel;
  uint32_t callback_channel;
} GLOBALGRID_PORT_MAPPING;

//TODO: NOTE To make encryption more secure, applications should use a counter variable that is added to the packet
//and incremented each time a packet is sent. This will add more entropy to the data stream and make it less
//vulnerable to cryptoanalysis attacks.
static inline void XorBlock(uint64_t* current, const uint64_t* prev) {
  current[0] ^=prev[0];
  current[1] ^=prev[1]; 
}
static void gg_port_destroy(void* thisptr) {
  delete (GLOBALGRID_PORT_MAPPING*)thisptr;
}
static void gg_recv(void* thisptr, unsigned char* src, int32_t srcPort, unsigned char* data, size_t sz) {
  GLOBALGRID_PORT_MAPPING* mapping = (GLOBALGRID_PORT_MAPPING*)thisptr;
  unsigned char* response = new unsigned char[4+16+4+sz];
  memcpy(response,&mapping->callback_channel,4);
  memcpy(response+4,src,16);
  memcpy(response+4+16,&srcPort,4);
  //TODO: Decrypt data
  unsigned char key[32];
  if(GGDNS_Symkey(src,key) && sz % 16 == 0) {
    for(size_t i = 16;i<sz;i+=16) {
      AES_Decrypt(key,data+i);
      XorBlock((uint64_t*)(data+i),(uint64_t*)(data+i-16));
    }
  }
  memcpy(response+4+16+4,data,sz);
  Platform_Channel_Transmit(mapping->channel,response,4+16+4+sz);
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
       uint32_t len = buffer.len;
       unsigned char* data = (unsigned char*)buffer.Increment(len);
       unsigned char gaddr[16];
       unsigned char key[32];
       unsigned char* response = new unsigned char[4+1];
       memcpy(response,&len,4);
       if(GGDNS_ResolveHost(auth,dest,gaddr,key)) {
	 //Encrypt
	 AES_Encrypt(key,data);
	 for(size_t i = 16;i<len;i+=16) {
	   XorBlock((uint64_t*)(data+i),(uint64_t*)(data+i-16));
	   AES_Encrypt(key,data+i);
	 }
	 GlobalGrid_Send(mngr->nativePtr,gaddr,callback_channel,port,data,len);
	  
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
     {
       uint32_t portno;
       buffer.Read(portno);
       ReceiveCallback cb;
       cb.onReceived = gg_recv;
       cb.onDestroyed = gg_port_destroy;
       GLOBALGRID_PORT_MAPPING* mapping = new GLOBALGRID_PORT_MAPPING();
       mapping->callback_channel = callback_channel;
       mapping->channel = channel;
       cb.thisptr = mapping;
       GlobalGrid_OpenPort(mngr->nativePtr,portno,cb);
     }
       break;
     case 3:
       //Request domain name
     {
       void* a;
       void(*b)(void*,unsigned char*,size_t);
       a = C([&](unsigned char* data, size_t len){
	 unsigned char* buffy = new unsigned char[4+len];
	 memcpy(buffy,&callback_channel,4);
	 memcpy(buffy+4,data,len);
	 Platform_Channel_Transmit(channel,buffy,4+len);
	 delete[] buffy;
      },b);
       GGDNS_MakeDomain(buffer.ReadString(),buffer.ReadString(),auth,a,b);
       
     }
       break;
     case 4:
       //Make tez catz very happy
       //Wez REALLY liekz Mudkipz!
       //lolcat.
     {
       unsigned char mander[16];
       uuid_generate(mander);
       char izard[256];
       uuid_unparse(mander,izard);
       void* a;
       void(*b)(void*,unsigned char*,size_t);
       a = C([&](unsigned char* data, size_t len){
	 unsigned char* buffy = new unsigned char[4+len];
	 memcpy(buffy,&callback_channel,4);
	 memcpy(buffy+4,data,len);
	 Platform_Channel_Transmit(channel,buffy,4+len);
	 delete[] buffy;
      },b);
       GGDNS_MakeDomain(izard,"",auth,a,b);
     }
       break;
     case 5:
       //Sign record and generate receipt
     {
       NamedObject obj;
       obj.bloblen = buffer.len;
       obj.blob = (unsigned char*)buffer.Increment(obj.bloblen);
       obj.authority = auth;
       void* a;
       void(*b)(void*,bool);
       a = C([&](bool ean){
	 
      },b);
       unsigned char mander[16];
       char izard[256];
       uuid_generate(mander);
       uuid_unparse(mander,izard);
       GGDNS_MakeObject(izard,&obj,a,b);
       size_t len = 4+strlen(izard)+1+obj.siglen;
       unsigned char* response = new unsigned char[len];
       memcpy(response,&callback_channel,4);
       memcpy(response+4,izard,strlen(izard+1));
       memcpy(response+4+strlen(izard)+1,obj.signature,obj.siglen);
       Platform_Channel_Transmit(channel,response,len);
       delete[] response;
     }
       break;
  }
}catch(const char* er) {
 }
      });
  
}

int main(int argc, char** argv) {
    std::shared_ptr<P2PConnectionManager> mngr = std::make_shared<P2PConnectionManager>();
    InternetProtocol ip(3701,mngr);
    mngr->RegisterProtocol(&ip);
    GGDNS_Init(mngr->nativePtr);
    ::mngr = mngr;
   
    if(argv[1] == std::string("demon")) {
      

      auth = argv[2];
      //Angels and Daemons!
      void* server = Platform_Open_Named_Channel(argv[3]);
      while(true) {
	Platform_Channel_ReadMsg(server,0,server_receivemsg);
      }
    }else {
        if(argv[1] == std::string("listID")) {
            void* a;
            bool(*b)(void*,const char*);
            a = C([&](const char* m){
                printf("%s\n",m);
                return true;
            },b);
            GGDNS_EnumPrivateKeys(a,b);
        }else {
        printf("HELP -- Usage\ndemon authID chanID\nlistID\n");
        }
    }
  
  
return 0;
}
