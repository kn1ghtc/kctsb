
#include <kctsb/math/bignum/thread.h>

#ifdef KCTSB_THREADS

#include <thread>
#include <sstream>

#endif



KCTSB_START_IMPL


const std::string& CurrentThreadID()
{
   KCTSB_TLS_LOCAL(std::string, ID);
   static KCTSB_CHEAP_THREAD_LOCAL bool initialized = false;

   if (!initialized) {
#ifdef KCTSB_THREADS
      std::stringstream ss;
      ss << std::this_thread::get_id();
      ID = ss.str();
#else
      ID = "0";
#endif
      initialized = true;
   }

   return ID;
}



KCTSB_END_IMPL
