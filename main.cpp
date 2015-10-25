/*
	This file is part of the GlobalGrid Protocol Suite.

    GlobalGrid Protocol Suite is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    GlobalGrid Protocol Suite is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with GlobalGrid Protocol Suite.  If not, see <http://www.gnu.org/licenses/>.
*/



#include <OpenAuth.h>
#include <GlobalGrid.h>
#include <InternetProtocol.h>
#include <string>
#include <iostream>
#include "GGRouter.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "sqlite3.h"
using namespace GlobalGrid;
using namespace LightThread;


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
  //TODO: Decrypt data, need to get a way to get this XOR algorithm to work in-place (or not, this may not be possible; so for now we'll copy it a bunch of times, note this is not designed to protect against kernel memory leaks)
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
       uint32_t srcport;
       uint32_t destport;
       buffer.Read(srcport);
       buffer.Read(destport);
       uint64_t enckey[2];
       bool haskey = GGDNS_Symkey(id,(unsigned char*)enckey);
       size_t sz = buffer.len;
       unsigned char* data = (unsigned char*)buffer.Increment(buffer.len);
       uint64_t* encdat = new uint64_t[sz/8];
       memcpy(encdat,data,sz);
       AES_Encrypt((unsigned char*)enckey,(unsigned char*)encdat,(unsigned char*)encdat);
       size_t lsize = sz/8;
       for(size_t i = 2;i<lsize;i+=2) {
	 XorBlock(encdat+i,encdat+i-1); //XOR with previous ciphertext
	 AES_Encrypt((unsigned char*)enckey,(unsigned char*)(encdat+i),(unsigned char*)(encdat+i)); //Encrypt
       }
       GlobalGrid_Send(mngr->nativePtr,id,srcport,destport,data,sz);
       delete[] encdat;
       break;
     case 7:
       //TODO: Implement client-side starting here
       //Retrieve ID of NamedObject
       bool found;
      std::string DotQuery(buffer.ReadString(),&found);
       
       break;
  }
}catch(const char* er) {
 }
      });
  
}
static void inserthandler(void* thisptr, NamedObject* obj,const char* name) {
  printf("Added new object with ID %s signed by %s\n",name,obj->authority);
  try {
    obj->blob+=4;
    obj->bloblen-=4;
    BStream str(obj->blob,obj->bloblen);
    if(std::string(str.ReadString()) == std::string("DNS-ENC")) {
      char* dname = str.ReadString();
      char* parent = str.ReadString();
      printf("DNS ENC advertisement for %s.%s (NOTE: Not yet validated; the domain may or may not actually exist)\n",dname,parent);
    }
  }catch(const char* mander) {
  }
}
static void writefile(void* thisptr, unsigned char* data, size_t len) {
  write(STDOUT_FILENO,data,len);
  
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
    
    GGDNS_SetInsertionHandler(0,inserthandler);
    RetryOperation([](std::function<void()> cancel){
      int scount = GGDNS_ObjectsSynchronizing();
      if(scount) {
	printf("Replicating %i objects.\n",scount);
      }
    },800,-1,[](){});
    if(argv[1] == std::string("demon")) {
      

      auth = argv[2]; //signing key
      //Angels and Daemons!
      void* server = Platform_Open_Named_Channel(argv[3]); //channel ID
      if(argc>=5) {
      
      domain = argv[4]; //local DNS name
      bool resolved;
      std::string qres = DotQuery(domain.c_str(),&resolved);
      if(qres.empty()) {
	printf("ERROR: Unable to resolve domain authority chain -- invalid Internet or malformed name. If you want to make an Internet, please run the makeinet command prior to assigning a domain name.\n");
	printf("FATAL ERROR.\n");
	sleep(-1);
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
	  char auth[256];
	  NamedObject obj;
	  obj.blob = domdat;
	  obj.bloblen = domlen;
	  obj.authority = auth;
	  void(*f)(void*,NamedObject*);
	  void* g = C([&](NamedObject* robj){
	    if(robj == 0) {
	      //TODO: Fix this; something goofy goes on during domain registration
	      printf("TODO: Bug found\n");
	    abort();
	      
	    }
	    memcpy(obj.authority,robj->authority,strlen(robj->authority)+1);
	    
	  },f);
	  OpenNet_Retrieve(GGDNS_db(),qres.data(),g,f);
	  unsigned char guid[16];
	  char name[256];
	  uuid_generate(guid);
	  uuid_unparse(guid,name);
	  bool s = OpenNet_HasPrivateKey(GGDNS_db(),obj.authority);
	  qres = name;
	  if(!s) {
	    int fd = open("request.dat",O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
	    write(fd,domdat,domlen);
	    close(fd);
	    printf("FATAL ERROR: Unable to sign domain. You don't have authority over the parent domain (only %s does). A domain registration request has been created, and stored in the file called request.dat. Please submit this file to the authority for the parent domain, and request that it be signed.\n",obj.authority);
	    sleep(-1);
	    return -3;
	  }
	    delete[] domdat;
	GGDNS_MakeObject(name,&obj,0,0);
	  
	  
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
	  }else {
	    if(argv[1] == std::string("signrecord")) {
	      NamedObject obj;
	      unsigned char izard[1024]; //Limit object size to 1KB
	      int count = read(STDIN_FILENO,izard,1024);
	      obj.authority = argv[2];
	      obj.blob = izard;
	      obj.bloblen = count;
	      unsigned char id[16];
	      uuid_generate(id);
	      char id_str[256];
	      memset(id_str,0,256);
	      uuid_unparse(id,id_str);
	      GGDNS_MakeObject(id_str,&obj,0,0);
	      printf("Object created successfully.\n");
	      return 0;
	    }else {
	      if(argv[1] == std::string("addiproute")) {
		in_addr_t addr = inet_addr(argv[2]);
		int portno = atoi(argv[3]);
		ip.AddRoute(addr,htons(portno));
		printf("Route added to database.\n");
		return 0;
	      }else {
		if(argv[1] == std::string("backup")) {
		  GGDNS_Backup(0,writefile);
		  abort();
		}else {
		  if(argv[1] == std::string("restore")) {
		    std::vector<unsigned char> bdata;
		    unsigned char buffy[2048];
		    
		    int count;
		    while((count = read(STDIN_FILENO,buffy,2048))>0) {
		      size_t prevsz = bdata.size();
		      bdata.resize(bdata.size()+count);
		      memcpy(bdata.data()+prevsz,buffy,count);
		      
		    }
		    GGDNS_RestoreBackup(bdata.data(),bdata.size());
		    abort();
		    
		  }
		}
	      }
	    }
	  }
        printf("HELP -- Usage\ndemon authID chanID domname\nlistID\nmakeinet auth\nsignrecord auth -- signs a record with the specified key and adds it to GGDNS.\naddiproute ipaddr portno -- Adds an IP route.\nBackup -- Writes a backup of the entire database to stdout.\nRestore -- Restores a backup from stdin.");
        }
    }
  
  
return 0;
}
