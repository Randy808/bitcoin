// Copyright (c) 2016-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/rbf.h>

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/moneystr.h>
#include <util/rbf.h>

<<<<<<< HEAD
#include <limits>
#include <vector>

=======
//RANDY_COMMETED
//Gets the rbf state of a transaction. A transaction is replacable if it signals rbf or if any of it's ancestor signals opt-in rbf
>>>>>>> 38a46344c (Made some comments to help me understand.)
RBFTransactionState IsRBFOptIn(const CTransaction& tx, const CTxMemPool& pool)
{
    //Make sure there's a lock on cs
    AssertLockHeld(pool.cs);

<<<<<<< HEAD
    CTxMemPool::setEntries ancestors;
=======
    //Create set entries that represent 'ancestors'
    CTxMemPool::setEntries setAncestors;
>>>>>>> 38a46344c (Made some comments to help me understand.)

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
<<<<<<< HEAD
    if (!pool.exists(GenTxid::Txid(tx.GetHash()))) {
=======
    //B_END

    //If the transaction doesn't exist in the mempool
    if (!pool.exists(tx.GetHash())) {
        //Say the state is unknown because the node doesn't have this transaction
>>>>>>> 38a46344c (Made some comments to help me understand.)
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
<<<<<<< HEAD
    pool.CalculateMemPoolAncestors(entry, ancestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    for (CTxMemPool::txiter it : ancestors) {
=======

    //Call another method to calculate the ancestors
    pool.CalculateMemPoolAncestors(entry, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    //For every ancestor entry (which is of type <txiter, CompareIteratorByHash>)
    for (CTxMemPool::txiter it : setAncestors) {
        //If the ancestor's transaction signals rbf
>>>>>>> 38a46344c (Made some comments to help me understand.)
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

std::optional<std::string> GetEntriesForConflicts(const CTransaction& tx,
                                                  CTxMemPool& pool,
                                                  const CTxMemPool::setEntries& iters_conflicting,
                                                  CTxMemPool::setEntries& all_conflicts)
{
    AssertLockHeld(pool.cs);
    const uint256 txid = tx.GetHash();
    uint64_t nConflictingCount = 0;
    for (const auto& mi : iters_conflicting) {
        nConflictingCount += mi->GetCountWithDescendants();
        // BIP125 Rule #5: don't consider replacing more than MAX_BIP125_REPLACEMENT_CANDIDATES
        // entries from the mempool. This potentially overestimates the number of actual
        // descendants (i.e. if multiple conflicts share a descendant, it will be counted multiple
        // times), but we just want to be conservative to avoid doing too much work.
        if (nConflictingCount > MAX_BIP125_REPLACEMENT_CANDIDATES) {
            return strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                             txid.ToString(),
                             nConflictingCount,
                             MAX_BIP125_REPLACEMENT_CANDIDATES);
        }
    }
    // Calculate the set of all transactions that would have to be evicted.
    for (CTxMemPool::txiter it : iters_conflicting) {
        pool.CalculateDescendants(it, all_conflicts);
    }
    return std::nullopt;
}

std::optional<std::string> HasNoNewUnconfirmed(const CTransaction& tx,
                                               const CTxMemPool& pool,
                                               const CTxMemPool::setEntries& iters_conflicting)
{
    AssertLockHeld(pool.cs);
    std::set<uint256> parents_of_conflicts;
    for (const auto& mi : iters_conflicting) {
        for (const CTxIn& txin : mi->GetTx().vin) {
            parents_of_conflicts.insert(txin.prevout.hash);
        }
    }

    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        // BIP125 Rule #2: We don't want to accept replacements that require low feerate junk to be
        // mined first.  Ideally we'd keep track of the ancestor feerates and make the decision
        // based on that, but for now requiring all new inputs to be confirmed works.
        //
        // Note that if you relax this to make RBF a little more useful, this may break the
        // CalculateMempoolAncestors RBF relaxation which subtracts the conflict count/size from the
        // descendant limit.
        if (!parents_of_conflicts.count(tx.vin[j].prevout.hash)) {
            // Rather than check the UTXO set - potentially expensive - it's cheaper to just check
            // if the new input refers to a tx that's in the mempool.
            if (pool.exists(GenTxid::Txid(tx.vin[j].prevout.hash))) {
                return strprintf("replacement %s adds unconfirmed input, idx %d",
                                 tx.GetHash().ToString(), j);
            }
        }
    }
    return std::nullopt;
}

std::optional<std::string> EntriesAndTxidsDisjoint(const CTxMemPool::setEntries& ancestors,
                                                   const std::set<uint256>& direct_conflicts,
                                                   const uint256& txid)
{
    for (CTxMemPool::txiter ancestorIt : ancestors) {
        const uint256& hashAncestor = ancestorIt->GetTx().GetHash();
        if (direct_conflicts.count(hashAncestor)) {
            return strprintf("%s spends conflicting transaction %s",
                             txid.ToString(),
                             hashAncestor.ToString());
        }
    }
    return std::nullopt;
}

std::optional<std::string> PaysMoreThanConflicts(const CTxMemPool::setEntries& iters_conflicting,
                                                 CFeeRate replacement_feerate,
                                                 const uint256& txid)
{
    for (const auto& mi : iters_conflicting) {
        // Don't allow the replacement to reduce the feerate of the mempool.
        //
        // We usually don't want to accept replacements with lower feerates than what they replaced
        // as that would lower the feerate of the next block. Requiring that the feerate always be
        // increased is also an easy-to-reason about way to prevent DoS attacks via replacements.
        //
        // We only consider the feerates of transactions being directly replaced, not their indirect
        // descendants. While that does mean high feerate children are ignored when deciding whether
        // or not to replace, we do require the replacement to pay more overall fees too, mitigating
        // most cases.
        CFeeRate original_feerate(mi->GetModifiedFee(), mi->GetTxSize());
        if (replacement_feerate <= original_feerate) {
            return strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                             txid.ToString(),
                             replacement_feerate.ToString(),
                             original_feerate.ToString());
        }
    }
    return std::nullopt;
}

std::optional<std::string> PaysForRBF(CAmount original_fees,
                                      CAmount replacement_fees,
                                      size_t replacement_vsize,
                                      CFeeRate relay_fee,
                                      const uint256& txid)
{
    // BIP125 Rule #3: The replacement fees must be greater than or equal to fees of the
    // transactions it replaces, otherwise the bandwidth used by those conflicting transactions
    // would not be paid for.
    if (replacement_fees < original_fees) {
        return strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                         txid.ToString(), FormatMoney(replacement_fees), FormatMoney(original_fees));
    }

    // BIP125 Rule #4: The new transaction must pay for its own bandwidth. Otherwise, we have a DoS
    // vector where attackers can cause a transaction to be replaced (and relayed) repeatedly by
    // increasing the fee by tiny amounts.
    CAmount additional_fees = replacement_fees - original_fees;
    if (additional_fees < relay_fee.GetFee(replacement_vsize)) {
        return strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                         txid.ToString(),
                         FormatMoney(additional_fees),
                         FormatMoney(relay_fee.GetFee(replacement_vsize)));
    }
    return std::nullopt;
}
