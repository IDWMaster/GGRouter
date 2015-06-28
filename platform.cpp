#include <sys/socket.h>
#include <sys/un.h>
#include <string>
#include <unistd.h>
#include <memory>
#include <map>
class IDisposable {
public:
  virtual ~IDisposable(){};
};

template<typename T>
class NativeObject:public IDisposable {
public:
  T obj;
  NativeObject(const T& val):obj(val) {
    
  }
  NativeObject() {
  }
};

template<typename T>
static void* MakeObject(const T& val) {
  return new NativeObject<T>(val);
}
template<typename T>
static T& GetObject(void* value) {
  return ((NativeObject<T>*)value)->obj;
}


class ManagedSocket:public IDisposable {
public:
  int fd;
  fd_set lst;
  std::map<int,ManagedSocket*> children;
  ManagedSocket(int fd) {
    this->fd = fd;
    FD_ZERO(&lst);
    FD_SET(fd,&lst);
  }
  ~ManagedSocket() {
    close(fd);
  }
};

extern "C" {
  void Platform_Free(void* obj) {
    delete (IDisposable*)obj;
  }
  void* Platform_Open_Named_Channel(const char* name) {
    struct sockaddr_un u;
    u.sun_family = AF_UNIX;
    std::string mstr = std::string("/tmp/GlobalGrid_")+name;
    memcpy(u.sun_path,mstr.data(),mstr.size()+1);
    int s = socket(AF_UNIX,SOCK_STREAM,0);
    unlink(mstr.data());
    bind(s,(struct sockaddr*)&u,sizeof(u));
    listen(s,50);
    return new ManagedSocket(s);
  }
  
  void* Platform_Channel_Connect(const char* name) {
     struct sockaddr_un u;
    u.sun_family = AF_UNIX;
    std::string mstr = std::string("/tmp/GlobalGrid_")+name;
    memcpy(u.sun_path,mstr.data(),mstr.size()+1);
    int q = socket(AF_UNIX,SOCK_STREAM,0);
    connect(q,(struct sockaddr*)&u,sizeof(u));
    return new ManagedSocket(q);
  }
  
  void Platform_Channel_Transmit(void* channel, void* data, size_t len) {
    ManagedSocket* s = (ManagedSocket*)channel;
    unsigned char* blackhole = (unsigned char*)malloc(4+len);
    memcpy(blackhole,&len,4);
    memcpy(blackhole+4,data,len);
    send(s->fd,blackhole, 4+len,0);
    free(blackhole);
  }
  
  void Platform_Channel_Receive(void* channel, void* thisptr, void(*callback)(void*,void*,size_t)) {
    ManagedSocket* s = (ManagedSocket*)channel;
    uint32_t len;
    read(s->fd,&len,4);
    void* msg = malloc(len);
    if(msg) {
      read(s->fd,msg,len);
      callback(thisptr,msg,len);
      free(msg);
    }
  }
  
  void Platform_Channel_ReadMsg(void* channel, void* thisptr, void(*callback)(void*,void*,void*,size_t)) {
    ManagedSocket* s = (ManagedSocket*)channel;
    fd_set ready = s->lst;
    int numReady = select(FD_SETSIZE,&ready,0,0,0);
    for(int i = 0;i<FD_SETSIZE;i++) {
      if(FD_ISSET(i,&ready)) {
	//We have either a connection request (new socket), or data on existing socket
	if(i == s->fd) {
	  //New client
	  int newfd = accept(s->fd,0,0);
	  FD_SET(newfd,&s->lst);
	  s->children[newfd] = new ManagedSocket(newfd);
	}else {
	  
	  //Existing client
	  //Frame is prefixed with 32-bit size
	  uint32_t len;
	  if(read(i,&len,4)<=0) {
	    //Client disconnect
	    close(i);
	    FD_CLR(i,&s->lst);
	    delete s->children[i];
	  }else {
	  void* buffy = malloc(len);
	  if(buffy) {
	    read(i,buffy,len);
	    callback(thisptr,(void*)s->children[i],buffy,len);
	    free(buffy);
	  }
	  }
	}
      }
    }
  }

}