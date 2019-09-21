//
//  rsaUtil.cpp
//  kcalg
//
//  Created by knightc on 2019/8/8.
//  Copyright © 2019 knightc. All rights reserved.
//

#include "rsaUtil.hpp"
#include <fstream>


void oula(const ZZ p , const ZZ q , ZZ &n ) {
    
    n = (p-1) * (q-1);
}

void SaveKey(const ZZ pubKey[],const ZZ privKey[])
{
   
    fstream fpublic, fprivate;
    fpublic.open ( "PublicKey.txt", ios::out );
    fprivate.open( "PrivateKey.txt", ios::out );

    fpublic << pubKey[0] ;    fpublic << "\n\n";    fpublic << pubKey[1] ;
    fprivate<< privKey[0] ;    fprivate<< "\n\n";    fprivate<< privKey[1];
    
    cout<<"[ ��Կ�������! ]"<<endl;
    cout<<"��Կ�������ļ�:   PublicKey.txt  "<<endl;
    cout<<"˽Կ�������ļ�:   PrivateKey.txt "<<endl;
    fpublic.close();
    fprivate.close();
}
