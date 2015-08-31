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
  //TODO: Decrypt data, need to get a way to get this XOR algorithm to work in-place
  unsigned char* plaintext = (unsigned char*)(new uint64_t[sz/8]);
  unsigned char* ciphertext = (unsigned char*)(new uint64_t[sz/8]);
  memcpy(ciphertext,data,sz);
  data = ciphertext;
  unsigned char key[32];
  if(GGDNS_Symkey(src,key) && sz % 16 == 0) {
    AES_Decrypt(key,plaintext,data);
    for(size_t i = 16;i<sz;i+=16) {
      AES_Decrypt(key,plaintext+i,data+i);
      XorBlock((uint64_t*)data,(uint64_t*)(plaintext-16));
    }
  }
  memcpy(response+4+16+4,plaintext,sz);
  delete[] plaintext;
  delete[] ciphertext;
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
       //Resolve DNS address (dot notation) to GUID
     {
       char* name = buffer.ReadString();
       unsigned char guid[16];
       unsigned char key[32];
       GGDNS_ResolveHost(auth,name,guid,key);
       unsigned char response[4+16];
       memcpy(response, &callback_channel,4);
       memcpy(response+4,guid,16);
       Platform_Channel_Transmit(channel,response,4+16);
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
     case 6:
       //TRANSMIT packet
       unsigned char id[16];
       buffer.Read(id);
       uint64_t enckey[2];
       bool haskey = GGDNS_Symkey(id,(unsigned char*)enckey);
       size_t sz = buffer.len;
       unsigned char* data = (unsigned char*)buffer.Increment(buffer.len);
       uint64_t* encdat = new uint64_t[sz/8];
       memcpy(encdat,data,sz);
       AES_Encrypt((unsigned char*)enckey,(unsigned char*)encdat,(unsigned char*)encdat);
       //TODO: Complete this
       delete[] encdat;
       break;
  }
}catch(const char* er) {
 }
      });
  
}
static std::string domain;
int main(int argc, char** argv) {
  printf("Starting GlobalGrid connection manager....\n");  
  std::shared_ptr<P2PConnectionManager> mngr = std::make_shared<P2PConnectionManager>();
    InternetProtocol ip(3701,mngr);
    mngr->RegisterProtocol(&ip);
    GGDNS_Init(mngr->nativePtr);
    ::mngr = mngr;
   printf("GlobalGrid protocol active\n");
    
    
    if(argv[1] == std::string("demon")) {
      

      auth = argv[2]; //signing key
      //Angels and Daemons!
      void* server = Platform_Open_Named_Channel(argv[3]); //channel ID
      domain = argv[4]; //local DNS name
      bool resolved;
      std::string qres = DotQuery(domain.c_str(),&resolved);
      if(qres.empty()) {
	printf("ERROR: Unable to resolve domain authority chain -- invalid Internet or malformed name. If you want to make an Internet, please run the makeinet command prior to assigning a domain name.\n");
	printf("FATAL ERROR. HALT\n");
	return -1;
      }
      printf("Query for domain registration returned: %s\n",qres.data());
      if(!resolved) {
	printf("WARNING: Name resolution failed at component %s\n",qres.data());
	
	std::string subDomain = domain.substr(0,domain.find_first_of("."));
	void(*a)(void*,unsigned char*,size_t);
	unsigned char* domdat = 0;
	size_t domlen = 0;
	void* b = C([&](unsigned char* data, size_t len){
	  if(data) {
	    domdat = new unsigned char[len];
	    domlen = len;
	    memcpy(domdat,data,len);
	  }
	},a);
	printf("Making domain %s with parent %s...\n",subDomain.data(),qres.data());
	GGDNS_MakeDomain(subDomain.data(),qres.data(),auth,b,a);
	printf("Domain created\n");
	if(!domdat) {
	  printf("FATAL ERROR: Domain registration failure.\n");
	  return -2;
	}else {
	  NamedObject obj;
	  obj.blob = domdat;
	  obj.bloblen = domlen;
	  obj.authority = auth;
	  unsigned char guid[16];
	  char name[256];
	  uuid_generate(guid);
	  uuid_unparse(guid,name);
	  void(*c)(void*,bool);
	  bool s;
	  void* d = C([&](bool success){
	    s = success;
	  },c);
	  GGDNS_MakeObject(name,&obj,d,c);
	  delete[] domdat;
	  if(!s) {
	    printf("FATAL ERROR: Unable to sign domain. Insufficient privileges or security error.\n");
	    return -3;
	  }
	  
	}
      }
      printf("Verifying host-GUID mapping....\n");
      unsigned char output[16];
      unsigned char key[32];
      void* d;
      void(*c)(void*,unsigned char*,size_t);
      bool rval = false;
      d = C([&](unsigned char* data, size_t sz){
	if(data && sz>=16) {
	  rval = true;
	memcpy(output,data,16);
	}
      },c);
      GGDNS_GetGuidListForObject(qres.data(),d,c);
      unsigned char lguid[16];
      
      mngr->getID(lguid);
      if(!rval) {
	//Update host record
	printf("WARNING: Out-of-sync record. Attempting to update.\n");
	GGDNS_MakeHost(qres.data(),lguid,16);
	printf("NOTICE: GGDNS host record was out-of-sync and has been updated. It may take several minutes for the changes to propogate througout the network.\n");
	
      }else {
	printf("Checking record sync\n");
	if(memcmp(lguid,output,16)) {
	  printf("NOTICE: Network-wide routing tables updated. Local ID has been modified, to sync with DNS record.\n");
	  mngr->setID(lguid);
	}
      }
      
      
      
      
      printf("GGRouter successfully initialized. You are now securely connected and authenticated to the GlobalGrid. GGDNS registration is in-sync and no further action is required at this point.\n");
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
	  if(argv[1] == std::string("makeinet")) {
	    auth = argv[2];
	    unsigned char mander[16];
       uuid_generate(mander);
       char izard[256];
       memset(izard,0,256);
       uuid_unparse(mander,izard);
       void* a;
       void(*b)(void*,unsigned char*,size_t);
       unsigned char* d;
       size_t e;
       a = C([&](unsigned char* data, size_t len){
	 printf("Internet creation complete.\n");
	 BStream str(data,len);
	 str.ReadString();
	 printf("Created internet: %s\n",str.ReadString());
	 e = len;
	 d = new unsigned char[len];
	 memcpy(d,data,len);
      },b);
       printf("Making Tezh Interwebz %s\n",izard);
       GGDNS_MakeDomain(izard,"",auth,a,b);
       NamedObject obj;
       obj.blob = d;
       obj.bloblen = e;
       obj.authority = auth;
       void(*f)(void*,bool);
       void* g = C([&](bool s){},f);
       GGDNS_MakeObject(izard,&obj,g,f);
       delete[] d;
       printf("Made Tezh Interwebz %s\n",izard);
       
       return 0;
	  }
        printf("HELP -- Usage\ndemon authID chanID domname\nlistID\nmakeinet auth\n");
        }
    }
  
  
return 0;
}
