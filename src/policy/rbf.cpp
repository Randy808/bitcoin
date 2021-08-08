// Copyright (c) 2016-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/rbf.h>
#include <util/rbf.h>

//RANDY_COMMETED
//Gets the rbf state of a transaction. A transaction is replacable if it signals rbf or if any of it's ancestor signals opt-in rbf
RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool)
{
    //Make sure there's a lock on cs
    AssertLockHeld(pool.cs);

    //Create set entries that represent 'ancestors'
    CTxMemPool::setEntries setAncestors;

    //B_S
    // First check the transaction itself.
    //B_END

    //IF transaction passed in signals rbg
    if (SignalsOptInRBF(tx)) {
        //Return the state that it's replacable
        return RBFTransactionState::REPLACEABLE_BIP125;
    }

    //B_S
    // If this transaction is not in our mempool, then we can't be sure
    // we will know about all its inputs.
    //B_END

    //If the transaction doesn't exist in the mempool
    if (!pool.exists(tx.GetHash())) {
        //Say the state is unknown because the node doesn't have this transaction
        return RBFTransactionState::UNKNOWN;
    }

    //B_S
    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    //B_END

    //Make a uint called 'noLimit'
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();

    //Make a dummy string
    std::string dummy;

    //Find the transaction in the mempool using the transaction hash
    CTxMemPoolEntry entry = *pool.mapTx.find(tx.GetHash());

    //Call another method to calculate the ancestors
    pool.CalculateMemPoolAncestors(entry, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    //For every ancestor entry (which is of type <txiter, CompareIteratorByHash>)
    for (CTxMemPool::txiter it : setAncestors) {
        //If the ancestor's transaction signals rbf
        if (SignalsOptInRBF(it->GetTx())) {
            //return that it's signaling rbf
            return RBFTransactionState::REPLACEABLE_BIP125;
        }
    }

    //If the transaction and none of the transaction's ancestors signal rbf, say the rbf state is final
    return RBFTransactionState::FINAL;
}

//RANDY_COMMENTED
//This just checks a single transaction (no ancestor checks) since it doesn't take in a mempool (I guess the assumptin is the mempool is empty when this is called?)
RBFTransactionState IsRBFOptInEmptyMempool(const CTransaction& tx)
{
    //BITCOIN_START
    // If we don't have a local mempool we can only check the transaction itself.
    //BITCOIN_END
    //If the transaction signals rbf, then return the state as replacable, otherwise  say it's unknown
    return SignalsOptInRBF(tx) ? RBFTransactionState::REPLACEABLE_BIP125 : RBFTransactionState::UNKNOWN;
}
