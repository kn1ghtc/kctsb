//
//  CTSBLog.hpp
//  TNMP
//
//  Created by 兰怀玉 on 16/5/6.
//  Copyright © 2016年 兰怀玉. All rights reserved.
//

#ifndef CTSBLog_hpp
#define CTSBLog_hpp
//

/**
 * 用于输出log文件的类.
 */
#include <stdio.h>
#include <string>
#include <sstream>
#include <iostream>

#ifndef _WIN32
#include <unistd.h>
#endif

using namespace std;

namespace tsblog {
    
    
    class ICTSBLog
    {
    public:
        virtual void setPath(string path) = 0;
        
        virtual void writeLog(stringstream &logstream) = 0;
        
        virtual string getFileName(time_t timestamp = 0) = 0;
        
        virtual void close() = 0;
    };
    
    string getTimeStr();
    unsigned long getCurrentThreadID();
  
    ICTSBLog* initLogEx(string path);
    ICTSBLog* getInstanceEx();
};


#define INITTSBLOG(PATH) tsblog::initLogEx(PATH)
#define CTSBLOSELOG() tsblog::getInstanceEx()->close()

#ifdef _WIN32
#define TTSBLOG(logstr) try{   std::stringstream stream; stream <<" ["<<tsblog::getCurrentThreadID()<<"]"<<tsblog::getTimeStr()<<logstr; tsblog::getInstanceEx()->writeLog(stream); }catch(...){std::cout<<"++++Excecption occur on LOG++++++++"<<std::endl;}
#else
#define TTSBLOG(logstr) try{   std::stringstream stream; stream <<" ["<<getpid()<<","<<tsblog::getCurrentThreadID()<<"]"<<tsblog::getTimeStr()<<logstr; tsblog::getInstanceEx()->writeLog(stream); }catch(...){std::cout<<"++++Excecption occur on LOG++++++++"<<std::endl;}
#endif // _WIN32



#endif /* CTSBLog_hpp */
