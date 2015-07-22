#include <GGRouter.h>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
using namespace GGClient;


int main(int argc, char** argv) {
printf("Connecting to GlobalGrid connection manager....");
  GlobalGridConnectionManager mngr("main");
if(mngr.router.channel == 0) {
  printf("Error occured connecting to GlobalGrid demon. Please ensure the main instance is running.\n");
  return -1;
}
std::thread otr([](){
  if(open("config",O_RDONLY) == -1) {
    char input[4096];
    printf("Please specify an Internet to connect to, or leave blank to generate one.");
    std::string inetid;
    if(read(STDIN_FILENO,input,4096) == 0) {
      printf("Creating Internet\n");
      
      void(*a)(void*,BStream&);
      void* b = C([&](BStream& str){
	BStream record = str;
	record.ReadString(); //DNS-ENC header
	inetid = record.ReadString(); //Domain name
	printf("Registering Internet\n");
	void(*c)(void*,BStream&);
	void* d = C([&](BStream& receipt){
	  printf("Created Internet with ID %s. Please keep this for your records.\n",inetid.data());
	},c);
	mngr.SignRecord(str,c,d);
      },a);
      mngr.MakeCatz(b,a); //Yes; some people get a Bachelor of Arts.
      
    }else {
      inetid = input;
    }
    
    
  }
});
mngr.router.RunLoop();
return 0;
}
