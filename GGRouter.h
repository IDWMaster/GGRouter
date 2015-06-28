#ifndef GGRouter
#define GGRouter
extern "C" {
  void Platform_Free(void* obj);
  void* Platform_Open_Named_Channel(const char* name);
  void* Platform_Channel_Connect(const char* name);
  void Platform_Channel_Transmit(void* channel, void* data, size_t len);
  void Platform_Channel_Receive(void* channel, void* thisptr, void(*callback)(void*,void*,size_t));
  void Platform_Channel_ReadMsg(void* channel, void* thisptr, void(*callback)(void*,void*,void*,size_t));
  bool GGDNS_Symkey(const unsigned char* guid, unsigned char* output);
  
}
#endif