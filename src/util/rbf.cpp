// Copyright (c) 2016-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/rbf.h>

#include <primitives/transaction.h>

//RANDY_COMMENTED
//Signaling RBF just seems to involve having an 'nSequence' below the max RBF nSequence
//This function returns true if the 'nSequence' for any of the input transaction's inputs is less than 0xfffffffd (4294967293 in decimal)
bool SignalsOptInRBF(const CTransaction &tx)
{
    //For every transaction input in the transaction's vin
    for (const CTxIn &txin : tx.vin) {
        //If the input's sequence is below the rbf's max sequence number
        if (txin.nSequence <= MAX_BIP125_RBF_SEQUENCE) {
            //Then it can signal opt-in RBF
            return true;
        }
    }

    //Otherwise it doesn't singal rbf
    return false;
}
