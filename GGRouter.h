#ifndef GGRouter
#define GGRouter
#include <stddef.h>
#include <string.h>
#include <map>
#include <memory>
#include <OpenAuth.h>
#include <mutex>
#include <condition_variable>
#include <uuid/uuid.h>
extern "C" {
  void Platform_Free(void* obj);
  void* Platform_Open_Named_Channel(const char* name);
  void* Platform_Channel_Connect(const char* name);
  void Platform_Channel_Transmit(void* channel, void* data, size_t len);
  void Platform_Channel_Receive(void* channel, void* thisptr, void(*callback)(void*,void*,size_t));
  void Platform_Channel_ReadMsg(void* channel, void* thisptr, void(*callback)(void*,void*,void*,size_t));
  bool GGDNS_Symkey(const unsigned char* guid, unsigned char* output);
  
}



//GlobalGrid client library
#ifdef __cplusplus


static void recvcb(void* thisptr,void* packet, size_t sz);



class BStream {
public:
  unsigned char* buffer;
  size_t len;
  BStream(void* buffer, size_t len) {
    this->buffer = (unsigned char*)buffer;
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


namespace GGClient {
  class WaitHandle {
  public:
    Event evt;
    unsigned char* data;
    size_t len;
    std::mutex mtx;
    void Put(unsigned char* data, size_t len) {
      mtx.lock();
      this->data = new unsigned char[len];
      memcpy(this->data,data,len);
      mtx.unlock();
    }
    void Fetch() {
      mtx.lock();
    }
    void Unfetch() {
      if(data) {
	delete[] data;
	data = 0;
      }
      mtx.unlock();
    }
    WaitHandle() {
      data = 0;
    }
    void Wait() {
      evt.wait();
    }
    void Signal() {
      evt.signal();
    }
    ~WaitHandle() {
      if(data) {
	delete[] data;
      }
    }
  };
  
  
  ///Represents a connection to a router
  class Router {
  public:
    uint32_t currentChannel;
    void* channel;
    std::map<uint32_t,std::shared_ptr<WaitHandle>> channelBindings;
    std::vector<uint32_t> freeChannels;
    Router(const char* name) {
      channel = Platform_Channel_Connect(name);
      currentChannel = 0;
    }
    uint32_t Bind(std::shared_ptr<WaitHandle> wh) {
      uint32_t chid;
      if(!freeChannels.empty()) {
	chid = freeChannels[freeChannels.size()-1];
	freeChannels.pop_back();
      }else {
	chid = currentChannel;
	currentChannel++;
      }
      channelBindings[chid] = wh;
      return chid;
    }
    void Unbind(uint32_t entry) {
      channelBindings.erase(entry);
      freeChannels.push_back(entry);
    }
    void RunLoop() {
      while(true) {
	Platform_Channel_Receive(channel,this,recvcb);
      }
    }
    ~Router() {
      if(channel) {
      Platform_Free(channel);
      }
    }
  };
  class GlobalGridConnectionManager {
  public:
    Router router;
    GlobalGridConnectionManager(const char* routerName):router(routerName) {
      
    }
    //Resolves a hostname to a 16-byte GUID
    void GetHostnameEntry(const char* hostname, unsigned char* output) {
      std::shared_ptr<WaitHandle> handle = std::make_shared<WaitHandle>();
      uint32_t chid = router.Bind(handle);
      unsigned char* request = new unsigned char[1+4+strlen(hostname)+1];
      request[0] = 1;
      memcpy(request+1,&chid,4);
      memcpy(request+1+4,hostname,strlen(hostname)+1);
      Platform_Channel_Transmit(router.channel,request,1+4+strlen(hostname)+1);
      handle->Fetch();
      memcpy(output,handle->data,16);
      handle->Unfetch();
      router.Unbind(chid);
    }
    //Sends a raw packet to the specified GUID
    bool SendRaw(const void* buffer, size_t sz, unsigned char* dest, uint32_t srcPort, uint32_t destPort) {
      std::shared_ptr<WaitHandle> handle = std::make_shared<WaitHandle>();
      uint32_t chid = router.Bind(handle);
      unsigned char* mander = new unsigned char[4+16+4+4+sz];
      unsigned char* ptr = mander;
      memcpy(mander,&chid,4);
      ptr+=4;
      *ptr = 6;
      ptr++;
      memcpy(ptr,dest,16);
      ptr+=16;
      memcpy(ptr,&srcPort,4);
      ptr+=4;
      memcpy(ptr,&destPort,4);
      ptr+=4;
      memcpy(ptr,buffer,sz);
      Platform_Channel_Transmit(router.channel,mander,4+16+4+4+sz);
      delete[] mander;
      handle->Wait();
      router.Unbind(chid);
      return handle->data[0];
    }
    template<typename T>
    uint32_t RunServer(uint32_t portno,void* thisptr, void(*callback)(void*,const void*,size_t)) {
      std::shared_ptr<WaitHandle> wh = std::make_shared<WaitHandle>();
      unsigned char mander[4+1+4];
      uint32_t retval = router.Bind(wh);
      memcpy(mander,&retval,4);
      mander[4] = 2;
      memcpy(mander+4+1,&portno,4);
      Platform_Channel_Transmit(router.channel,mander,4+1+4);
      while(true) {
	wh->Fetch();
	{
	  BStream str(wh->data,wh->len);
	  unsigned char* guid = str.Increment(16);
	  uint32_t portno;
	  str.Read(portno);
	  callback(thisptr,str.buffer,str.len);
	}

	wh->Unfetch();
      }
    }
    bool Send(const void* buffer, size_t sz,unsigned char* dest, uint32_t srcPort, uint32_t destPort) {
      //Pad and align
      uint32_t osz = sz;
      sz+=4;
      size_t fullSz = sz+(16-(sz % 16));
      unsigned char* izard = new unsigned char[fullSz];
      memcpy(izard,&osz,4);
      memcpy(izard+4,buffer,osz);
      bool retval = SendRaw(izard,fullSz,dest,srcPort,destPort);
      delete[] izard;
      return retval;
    }
    //Lol. (Laugh out loud.)
    void MakeCatz(void* thisptr,void(*callback)(void*,BStream&)) {
      std::shared_ptr<WaitHandle> wh = std::make_shared<WaitHandle>();
      uint32_t chan = router.Bind(wh);
      unsigned char izard[4+1];
      memcpy(izard,&chan,4);
      izard[4] = 4;
      Platform_Channel_Transmit(router.channel,izard,5);
      wh->Wait();
      router.Unbind(chan);
      BStream d(wh->data,wh->len);
      callback(thisptr,d);
    }
    void RequestDomainName(const char* name, const char* parentAuthority,void* thisptr, void(*callback)(void*,BStream&)) {
      size_t len = 4+1+strlen(name)+1+strlen(parentAuthority)+1;
      unsigned char* mander = new unsigned char[len];
      std::shared_ptr<WaitHandle> wh = std::make_shared<WaitHandle>();
      uint32_t chan = router.Bind(wh);
      memcpy(mander,&chan,4);
      mander[4] = 3;
      memcpy(mander+4+1,name,strlen(name)+1);
      memcpy(mander+4+1+strlen(name)+1,parentAuthority,strlen(parentAuthority)+1);
      Platform_Channel_Transmit(router.channel,mander,len);
      wh->Wait();
      router.Unbind(chan);
      delete[] mander;
    }
    void SignRecord(BStream data,void* thisptr, void(*callback)(void*,BStream&)) {
      unsigned char* mander = new unsigned char[4+1+data.len];
      std::shared_ptr<WaitHandle> wh = std::make_shared<WaitHandle>();
      uint32_t chan = router.Bind(wh);
      memcpy(mander,&chan,4);
      mander[4] = 5;
      memcpy(mander+4+1,data.buffer,data.len);
      wh->Wait();
      router.Unbind(chan);
      BStream bs(wh->data,wh->len);
      callback(thisptr,bs);
      delete[] mander;
    }
  };



}


static void recvcb(void* thisptr, void* packet, size_t sz) {
  GGClient::Router* router = (GGClient::Router*)thisptr;
  BStream str(packet,sz);
  uint32_t chen;
  str.Read(chen);
  //Receive packet on channel
  if(router->channelBindings.find(chen) != router->channelBindings.end()){
    auto bot = router->channelBindings[chen];
    bot->Put(str.buffer,str.len);
  }
  
}

#endif

#endif