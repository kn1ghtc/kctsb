//
//  welcome.cpp
//  kcalg
//
//  Created by knightc on 2019/4/4.
//  Copyright © 2019 knightc. All rights reserved.
//

#include <cstdio> // c++ std header is no ".H",and add "c" to the first to support c std header
#include <cctype>
#include <string>
#include <vector>
#include <iostream>

#include "opentsb/cplus.h"

using namespace std;

 int strout()
{
    char teststring[]="welcome knightc" ;
    string welcome_s = "\n      it's your cpp world  \n" ;
    string Ten_welcome_s(10,'*');//one char
    unsigned long lengStr= 2 * Ten_welcome_s.size() + strlen(teststring) +2 ;
    string end_welcome_s(lengStr,'*');
    
    printf("%s %s %s \n ",Ten_welcome_s.c_str(), teststring,Ten_welcome_s.c_str());
    
    cout << welcome_s + "\n";
    
    string line;
    
//    while (getline(cin, line)) {  // "ctrl + D" is end
//        if (!line.empty()) {
//            cout << line << endl;
//        }
//    }
    
    system("pwd");
    
    printf("%s \n \n",end_welcome_s.c_str());
    
    //string's for
  decltype(welcome_s.size())  punct_cnt =0; //Declaration return type
    string  testForStr(" Hi1abc!    sss!");
    for (auto &c : testForStr) {
       // cout << c << endl;
        if (ispunct(c)) {
            punct_cnt++;
        }
//        if (islower(c)) {
//            c = toupper(c);
//        }
    }
    
    for (string::size_type i=0 ; i != testForStr.size() && !isspace(testForStr[i]); i++) { // if isspace then quit
        testForStr[i] =  toupper(testForStr[i]);
    }
    cout << punct_cnt  <<Ten_welcome_s << testForStr.size() <<"\n" << testForStr << "\n"<< endl;
    
    
    return 0;
    
}
