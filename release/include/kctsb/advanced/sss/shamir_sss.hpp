////
////  ShamirSSS.hpp
////  kcalg
////
////  Created by knightc on 2019/6/12.
////  Copyright © 2019 knightc. All rights reserved.
////
//
//#ifndef ShamirSSS_hpp
//#define ShamirSSS_hpp
//
//#include <stdio.h>
//#include "NTL//ZZ.h"
//#include <vector>
//
//
//class ShamirSSS {
//    public:typedef unsigned int UInt;typedef NTL::ZZ BigNumber;typedef std::vector<BigNumber> BigNrVec;
//    public:secretShamirSSS(UInt n, UInt k);
//    // Parameters:
//    //n - total number of people
//    //k - people need to discover
//    public:~ShamirSSS(void);
//    public:AccesSecret(const std::vector<UInt>& vPeople, const BigNrVec &vPeopleSecrets);
//    // Return the secret partsconst BigNrVec& GetSecretParts();
//    // The people from vPeople try to acces the secretbool
//    
//    private:GeneratePolynom();CalculateSharingParts();
//    // generates the base polynom fro the schemevoid
//    // calculate the sharing partsvoid
//    
//    private:BigNrVec m_vPolynom;
//    // coef of base polynom
//    // polynom[0] = the secretBigNrVec m_vSharingParts;
//    // secret parts know by each people UInt m_nN;
//    // total number of people which have a piece of secretUInt m_nK;
//    // nr of people need to discover the secret BigNumber m_bnPrimeNr;
//    // the prime number for modulo opration
//    
//};
//
//
//
//#endif /* ShamirSSS_hpp */
