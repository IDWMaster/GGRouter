#ifndef GGRouter
#define GGRouter
#include <stddef.h>
#include <string.h>
#include <map>
#include <memory>
#include <OpenAuth.h>
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


static void recvcb(void* thisptr,void* packet, size_t sz);
namespace GGClient {
  class AsyncChannelBinding {
  public:
    void(*callback)(void*,BStream&);
    void* thisptr;
  };
  ///Represents a connection to a router
  class Router {
  public:
    uint32_t currentChannel;
    void* channel;
    std::map<uint32_t,AsyncChannelBinding> channelBindings;
    std::vector<uint32_t> freeChannels;
    Router(const char* name) {
      channel = Platform_Channel_Connect(name);
      currentChannel = 0;
    }
    template<typename T>
    uint32_t Bind(const T& functor) {
      AsyncChannelBinding binding;
      binding.thisptr = C(functor,binding.callback);
      uint32_t chid;
      if(!freeChannels.empty()) {
	chid = freeChannels[freeChannels.size()-1];
	freeChannels.pop_back();
      }else {
	chid = currentChannel;
	currentChannel++;
      }
      channelBindings[chid] = binding;
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
      Platform_Free(channel);
    }
  };
  
  class GlobalGridConnectionManager {
  public:
    Router router;
    uint32_t nullch;
    GlobalGridConnectionManager(const char* routerName):router(routerName) {
      nullch = router.Bind([](BStream& str){});
    }
    void SendRaw(const void* buffer, size_t sz, const char* dest) {
      unsigned char* mander = new unsigned char[4+sz+1];
      unsigned char* ptr = mander;
      memcpy(mander,&nullch,4);
      ptr+=4;
      *ptr = 1;
      ptr++;
      memcpy(ptr,buffer,sz);
      Platform_Channel_Transmit(router.channel,mander,4+sz+1);
      delete[] mander;
    }
    template<typename T>
    uint32_t CreatePortMapping(uint32_t portno, const T& functor) {
      unsigned char mander[4+1+4];
      uint32_t retval = router.Bind(functor);
      memcpy(mander,&retval,4);
      mander[4] = 2;
      memcpy(mander+4+1,&portno,4);
      Platform_Channel_Transmit(router.channel,mander,4+1+4);
      return retval;
    }
    
    void Send(const void* buffer, size_t sz,const char* dest) {
      //Pad and align
      uint32_t osz = sz;
      sz+=4;
      size_t fullSz = sz+(16-(sz % 16));
      unsigned char* izard = new unsigned char[fullSz];
      memcpy(izard,&osz,4);
      memcpy(izard+4,buffer,osz);
      SendRaw(izard,fullSz,dest);
      delete[] izard;
    }
  };


static void recvb(void* thisptr, void* packet, size_t sz) {
  Router* router = (Router*)thisptr;
  BStream str(packet,sz);
  uint32_t chen;
  str.Read(chen);
  //Receive packet on channel
  if(router->channelBindings.find(chen) != router->channelBindings.end()){
    auto bot = router->channelBindings[chen];
    bot.callback(bot.thisptr,str);
  }
  
}

}
#endif

#endif