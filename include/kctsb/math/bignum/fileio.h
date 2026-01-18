
#ifndef KCTSB_fileio__H
#define KCTSB_fileio__H

#include <kctsb/math/bignum/tools.h>
#include <kctsb/math/bignum/vector.h>
#include <fstream>                                                              
#include <string>


KCTSB_OPEN_NNS


class FileList {
private:
   Vec< Vec<char> > data;

   FileList(const FileList&); // disable
   void operator=(const FileList&); // disable

public:
   FileList() { }
   void AddFile(const char *name);
   void RemoveLast();

   ~FileList();


};



void OpenWrite(KCTSB_SNS ofstream& s, const char *name);
// opens file for writing...aborts if fails

void OpenWrite(KCTSB_SNS ofstream& s, const char *name, FileList& flist);
// opens file for writing and adds name to flist

void OpenRead(KCTSB_SNS ifstream& s, const char *name);
// opens file for reading

void CloseWrite(KCTSB_SNS ofstream& s);
// closes s, checks for failure



const char *FileName(const char* stem, long d);
// builds the name from stem-DDDDD, returns pointer to buffer

const KCTSB_SNS string& UniqueID();
// ideally, a unique ID (across all processes and threads),
// but it may not be perfect (useful for generating unique 
// file names and seeding PRG).

KCTSB_CLOSE_NNS

#endif


