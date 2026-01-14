////
////  ShamirSSS.cpp
////  kcalg
////
////  Created by knightc on 2019/6/12.
////  Copyright © 2019 knightc. All rights reserved.
////
//
//#include "ShamirSSS.hpp"
//
//#include <iostream>
//using namespace std;
//// Parameters:
////n - total number of people
////k - people need to discover secret
//ShamirSSS::ShamirSSS(UInt n, UInt k) :
//m_nN(n), m_nK(k),
//m_vSharingParts(n),
//m_vPolynom(k)
//{
//
//    m_bnPrimeNr = NTL::GenPrime_ZZ(16, 100);
//    //m_bnPrimeNr = 11;
//    GeneratePolynom();
//    CalculateSharingParts();
//
//}
//
//ShamirSSScheme::~ShamirSSScheme(void)
//{
//
//
//}
//
//// Generate the base polynom for calcul
//// the coeficient are in the order-
////m_vPolynom[i] = coef for x^i
//// polynom[0] = the secret
//void ShamirSSScheme::GeneratePolynom()
//{
//
//    for (UInt i = 0; i < m_nK; i++)
//    {
//
//        NTL::RandomBnd(m_vPolynom[i], m_bnPrimeNr);
//        //cout << "pol[" << i << "] = " << m_vPolynom[i] << '\n';
//
//    }
//    //m_vPolynom[0] = 10;
//    //m_vPolynom[1] = 7;
//    //m_vPolynom[2] = 2;
//
//
//}
//
//void ShamirSSScheme::CalculateSharingParts()
//{
//
//    BigNumber aux;
//    for (UInt i = 0; i < m_nN; i++)
//    {
//
//        m_vSharingParts[i] = 0;
//        for (UInt j = 0; j < m_nK; j++)
//        {
//
//            NTL::PowerMod(aux, NTL::to_ZZ(i + 1), j, m_bnPrimeNr);
//            m_vSharingParts[i] = (m_vSharingParts[i] + m_vPolynom[j] * aux) % m_bnPrimeNr;
//
//        }
//        cout << "share[" << i << "] = " << m_vSharingParts[i] << '\n';
//
//    }
//
//    //m_vSharingParts[0] = 8;
//    //m_vSharingParts[1] = 10;
//    //m_vSharingParts[2] = 5;
//    //m_vSharingParts[3] = 4;
//    //m_vSharingParts[4] = 7;
//
//}
//
//const ShamirSSScheme::BigNrVec& ShamirSSScheme::GetSecretParts()
//{
//
//    return m_vSharingParts;
//
//}
//
//// return true if the secret was succesfuly recomposed
//// otherwise false
//bool ShamirSSScheme::AccesSecret(const std::vector<UInt>& vPeople, const ShamirSSScheme::BigNrVec &vPeopleSecrets)
//{
//
//    cout << "\nTrying to acces the secret...\n";
//    UInt peopleNr = (UInt)vPeople.size();
//    if (peopleNr != vPeopleSecrets.size())
//    {
//
//        cout << "People nr and secret nr are  not equal\n";
//        return false;
//
//    }
//
//    BigNumber secret, aux, aux1;
//    for (UInt i = 0; i < peopleNr; i++)
//    {
//
//        aux1 = 1;
//        for (UInt j = 0; j < peopleNr; j++)
//        {
//
//            if (vPeople[j] != vPeople[i])
//            {
//
//                aux = vPeople[j] - vPeople[i];
//                while (aux <= 0)
//                    aux += m_bnPrimeNr;
//                // cout << "aux: "<< aux << '\n';
//                MulMod(aux1, aux1, ((vPeople[j] + 1)*InvMod(aux, m_bnPrimeNr)) % m_bnPrimeNr, m_bnPrimeNr);
//                // cout << "aux1: "<< aux << '\n';
//
//            }
//
//        }
//        //cout << "aux1: "<< aux1 << '\n';
//        secret = (secret + vPeopleSecrets[i]*aux1) % m_bnPrimeNr;
//        //cout << "ss: " << ss << '\n';
//
//    }
//
//    cout << "Secret: " << m_vPolynom[0] << '\n';
//    cout << "\nSecret discovered: " << secret <<'\n';
//    if ( secret == m_vPolynom[0])
//    {
//
//        cout << "\nSecret Succefuly accesed\n";
//        return true;
//
//    }
//
//    cout << "\nAcces Denied!\n";
//    return false;
//
//}
