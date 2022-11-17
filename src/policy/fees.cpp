// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/fees.h>

#include <clientversion.h>
#include <consensus/amount.h>
#include <fs.h>
#include <logging.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/serfloat.h>
#include <util/system.h>
#include <util/time.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <stdexcept>
#include <utility>

static constexpr double INF_FEERATE = 1e99;

//RANDY_COMMENTED
//Converts FeeEstimateHorizon enum to a string value
std::string StringForFeeEstimateHorizon(FeeEstimateHorizon horizon)
{
    //Switch on the fee estimate parameter horizon
    switch (horizon) {
    //Changes the enum to the string "short" if equal to SHORT_HALFLIFE
    case FeeEstimateHorizon::SHORT_HALFLIFE: return "short";

    //Changes the enum to the string "medium" if equal to MED_HALFLIFE
    case FeeEstimateHorizon::MED_HALFLIFE: return "medium";

    //Changes the enum to the string "long" if equal to LONG_HALFLIFE
    case FeeEstimateHorizon::LONG_HALFLIFE: return "long";
    }
    //BITCOIN_START
    // no default case, so the compiler can warn about missing cases
    //BITCOIN_END
    //Fail assertion if the enum didn't match any of them
    assert(false);
}


namespace {

struct EncodedDoubleFormatter
{
    template<typename Stream> void Ser(Stream &s, double v)
    {
        s << EncodeDouble(v);
    }

    template<typename Stream> void Unser(Stream& s, double& v)
    {
        uint64_t encoded;
        s >> encoded;
        v = DecodeDouble(encoded);
    }
};

} // namespace


//RANDY_COMMENTED
//Pretty much a private class
//B_START
/**
 * We will instantiate an instance of this class to track transactions that were
 * included in a block. We will lump transactions into a bucket according to their
 * approximate feerate and then track how long it took for those txs to be included in a block
 *
 * The tracking of unconfirmed (mempool) transactions is completely independent of the
 * historical tracking of transactions that have been confirmed in a block.
 */
//B_END
class TxConfirmStats
{
private:
    //Define the buckets we will group transactions into
    const std::vector<double>& buckets;              // The upper-bound of the range for the bucket (inclusive)
    const std::map<double, unsigned int>& bucketMap; // Map of bucket upper-bound to index into all vectors by bucket

    // For each bucket X:
    // Count the total # of txs in each bucket
    // Track the historical moving average of this total over blocks
    std::vector<double> txCtAvg;

    // Count the total # of txs confirmed within Y blocks in each bucket
    // Track the historical moving average of these totals over blocks
    std::vector<std::vector<double>> confAvg; // confAvg[Y][X]

    // Track moving avg of txs which have been evicted from the mempool
    // after failing to be confirmed within Y blocks
    std::vector<std::vector<double>> failAvg; // failAvg[Y][X]

    // Sum the total feerate of all tx's in each bucket
    // Track the historical moving average of this total over blocks
    std::vector<double> m_feerate_avg;

    // Combine the conf counts with tx counts to calculate the confirmation % for each Y,X
    // Combine the total value with the tx counts to calculate the avg feerate per bucket

    double decay;

    //B_START
    // Resolution (# of blocks) with which confirmations are tracked
    //B_END

    //Gets initialized by constructor 'scale(_scale)'
    //scale is how many confirmations per period to track. Period number is taken from feestats construxtor
    unsigned int scale;

    // Mempool counts of outstanding transactions
    // For each bucket X, track the number of transactions in the mempool
    // that are unconfirmed for each possible confirmation value Y
    std::vector<std::vector<int>> unconfTxs; //unconfTxs[Y][X]
    // transactions still unconfirmed after GetMaxConfirms for each bucket
    std::vector<int> oldUnconfTxs;

    void resizeInMemoryCounters(size_t newbuckets);

public:
    /**
     * Create new TxConfirmStats. This is called by BlockPolicyEstimator's
     * constructor with default values.
     * @param defaultBuckets contains the upper limits for the bucket boundaries
     * @param maxPeriods max number of periods to track
     * @param decay how much to decay the historical moving average per block
     */
    TxConfirmStats(const std::vector<double>& defaultBuckets, const std::map<double, unsigned int>& defaultBucketMap,
                   unsigned int maxPeriods, double decay, unsigned int scale);

    /** Roll the circular buffer for unconfirmed txs*/
    void ClearCurrent(unsigned int nBlockHeight);

    /**
     * Record a new transaction data point in the current block stats
     * @param blocksToConfirm the number of blocks it took this transaction to confirm
     * @param val the feerate of the transaction
     * @warning blocksToConfirm is 1-based and has to be >= 1
     */
    void Record(int blocksToConfirm, double val);

    /** Record a new transaction entering the mempool*/
    unsigned int NewTx(unsigned int nBlockHeight, double val);

    /** Remove a transaction from mempool tracking stats*/
    void removeTx(unsigned int entryHeight, unsigned int nBestSeenHeight,
                  unsigned int bucketIndex, bool inBlock);

    /** Update our estimates by decaying our historical moving average and updating
        with the data gathered from the current block */
    void UpdateMovingAverages();

    /**
     * Calculate a feerate estimate.  Find the lowest value bucket (or range of buckets
     * to make sure we have enough data points) whose transactions still have sufficient likelihood
     * of being confirmed within the target number of confirmations
     * @param confTarget target number of confirmations
     * @param sufficientTxVal required average number of transactions per block in a bucket range
     * @param minSuccess the success probability we require
     * @param nBlockHeight the current block height
     */
    double EstimateMedianVal(int confTarget, double sufficientTxVal,
                             double minSuccess, unsigned int nBlockHeight,
                             EstimationResult* result = nullptr) const;

    //B_START
    /** Return the max number of confirms we're tracking */
    //B_END
    //The scale is defined in the CBLockPolicy's constructor for each feestats and the confAVg's size should be set equal to the period. So we have as many confirmations as we have for scale and periods
    unsigned int GetMaxConfirms() const { return scale * confAvg.size(); }

    /** Write state of estimation data to a file*/
    void Write(AutoFile& fileout) const;

    /**
     * Read saved state of estimation data from a file and replace all internal data structures and
     * variables with this state.
     */
    void Read(AutoFile& filein, int nFileVersion, size_t numBuckets);
};

//RANDY_COMMENTED
//This is the constructor for 'TxConfirmStats'. Initialize confAvg and failAvg vectors into sizes matching the 3rd parameter 'maxPeriods', and initialize each vector's contained double vectors to have the same size as the first param 'defaultBuckets'. Then initialize txCtAvg and m_feerate_avg to the 'defaultBuckets' size as well.
/*
maxPeriods: 3
defaultBuckets: 2
confAvg: | {1,2} | {1,2} | {1,2} |
failAvg: | {1,2} | {1,2} | {1,2} |
txCtAvg: {1,2}
m_feerate_avg: {1,2}

| period{ feerateBucket1{},feerateBucket2{} } |
*Each period contains recorded fees for all confirmationTimes that are within scale*periodIndex

*/
TxConfirmStats::TxConfirmStats(const std::vector<double>& defaultBuckets,
                               const std::map<double, unsigned int>& defaultBucketMap,
                               unsigned int maxPeriods, double _decay, unsigned int _scale)
    : buckets(defaultBuckets), bucketMap(defaultBucketMap), decay(_decay), scale(_scale)
{
    //Assert the scale value is positive
    assert(_scale != 0 && "_scale must be non-zero");
    //The confirmation avergae property, confAvg,is resized to equal maxPeriods
    confAvg.resize(maxPeriods);
    //The failing average property (for transactions evicted from mempool for not being confirmed),failAvg, is also set to the same size as maxPeriod
    failAvg.resize(maxPeriods);

    //For int i to maxPeriods, initialize the size of each double vector in the containing vectors that are confAvg and failAvg
    for (unsigned int i = 0; i < maxPeriods; i++) {
        //resize the average confirmations at every index to equal bucket size
        confAvg[i].resize(buckets.size());
        //resize the failing average at every index to equal bucket size
        failAvg[i].resize(buckets.size());
    }

    //Reize the transaction count average to the bucket size
    txCtAvg.resize(buckets.size());

    //resize the average fee rate
    m_feerate_avg.resize(buckets.size());

    //resize memory counters to bucket size
    resizeInMemoryCounters(buckets.size());
}

//RANDY_COMMENTED
//**Only called from 'Read' and on TxConfirmStats constructor
//Resize the unconfTxs to represent all the values of confirmations there could be and resize the vector at every index to the number of newbuckets there are. Then resize the oldUnconfTxs to the number of newbuckets.
void TxConfirmStats::resizeInMemoryCounters(size_t newbuckets)
{
    //BITCOIN_START
    // newbuckets must be passed in because the buckets referred to during Read have not been updated yet.
    //BITCOIN_END

    //Resize the vector of unconfirmed transactions to the return value of 'GetMaxConfirms'
    unconfTxs.resize(GetMaxConfirms());

    //For every unconfirmed transaction
    for (unsigned int i = 0; i < unconfTxs.size(); i++) {
        //resize the vector at the index, where the index represents the unconfirmed transaction count, to the number of total buckets there are
        unconfTxs[i].resize(newbuckets);
    }

    //Resize the old unconfirmed transactions to the current bucket size
    oldUnconfTxs.resize(newbuckets);
}


//RANDY_COMMENTED
//For every bucket of the given period (I'll call period confimration), clear the current unconfirmed transactions
//B_START
// Roll the unconfirmed txs circular buffer
//B_END
void TxConfirmStats::ClearCurrent(unsigned int nBlockHeight)
{
    //For every bucket index (not bucket *of* index)
    for (unsigned int j = 0; j < buckets.size(); j++) {
        //Add the unconfirmed transactions from n (the blockheight modulo'd with the currentUnconfTx size) and the bucket j
        //to the old unconfirmed transactions of bucket j
        oldUnconfTxs[j] += unconfTxs[nBlockHeight % unconfTxs.size()][j];

        //Set the unconfirmed transaction bucket we just emptied to 0
        //unconfTx should have a length of period*scale (or result of GetMaxConfirms(s))
        //We're setting the blockheight in the first period to 0
        unconfTxs[nBlockHeight % unconfTxs.size()][j] = 0;
    }
}


//RANDY_COMMENTED
//**Called from CBlockPolicyEstimator::processBlockTx
//Increment the bucket value count (with bucket index matching the feerate) for all periods represented by 'blocksToConfirm'. Also adds feerate to corresponding bucket index value in m_feerate_avg and increments txCtAvg at the same index.
/*
maxPeriods: 3
defaultBuckets: 2
confAvg: | {0,0} | {0,0} | {0,0} |
failAvg: | {1,2} | {1,2} | {1,2} |
txCtAvg: {1,2}
m_feerate_avg: {1,2}

(blocksToConfirm = 2, feerate = 3)
bucketIndex will round down feerate to *index* below bucket length, so the max index is 1 for max index of value 2. Uses bucketmap to convert feerate to bucket index
bucketIndex: 1
periodsToConfirm = blocksToConfirm will fall into a scale that will fall into a specific period
                 |_periodsToConfirm will cause all index after _periodsToConfirm to incremnet
confAvg: | {0,0} | {0,0} | {0,0} |
confAvg: | {0,0} | {0,0} | {0,0} |


| period{ feerateBucket1{},feerateBucket2{} } |
*Each period contains recorded fees for all confirmationTimes that are within scale*periodIndex

*/
void TxConfirmStats::Record(int blocksToConfirm, double feerate)
{
    //BITCOIN_START
    // blocksToConfirm is 1-based
    //BITCOIN_END

    //If the parameter is less than 1, return
    if (blocksToConfirm < 1)
        return;

    //Calculate periodsToConfirm by scaling the 'blocksToConfirm' parameter down by 'scale'. The blocksToConfirm has 'scale' added to it so the periodsToConfirm integer will start at '1' (since 'blocksToConfim' must be at least 1, and if the blocksToConfirm is set to 1 then the whole expression will resolve to 1).
    //blocksToConfirm has to be a multiple of (scale - 1) to get more periods to confirm
    // (blocksToConfirm-1)/scale + 1
    //Focused on granularity and doesn't have set period sizes
    int periodsToConfirm = (blocksToConfirm + scale - 1) / scale;

    //Make the bucketindex to increment equal to bucketMap's lower bound for the feerate given in the parameter
    //Bucket map is map from feerate threshold to bucket index
    //This gets the bucket index in 'buckets' that best matches the 'feerate'
    unsigned int bucketindex = bucketMap.lower_bound(feerate)->second;

    //For every period in confAvg, increment the bucket index by 1
    for (size_t i = periodsToConfirm; i <= confAvg.size(); i++) {
        confAvg[i - 1][bucketindex]++;
    }

    //Add 1 to the transaction count average at that bucketindex
    txCtAvg[bucketindex]++;

    //Add the fee rate to m_feerate_avg
    //Does m_feerate_avg actually compute an averge somehow or is it used in an average calculation
    m_feerate_avg[bucketindex] += feerate;
}


//RANDY_COMMENTED
//Called from processBlock
//Multiply every value in confAvg and failAvg (in every 2d index) by the decay
void TxConfirmStats::UpdateMovingAverages()
{
    //Assert that the confAvg first domension size (confirmations tracked for buckets) is equal to the failAvg size
    assert(confAvg.size() == failAvg.size());

    //For every index up to the bucket size
    for (unsigned int j = 0; j < buckets.size(); j++) {
        //And for ever confAvg index
        for (unsigned int i = 0; i < confAvg.size(); i++) {
            //Multiply the confAvg by the decay
            confAvg[i][j] *= decay;
            //And multiply the failAvg by the decay
            failAvg[i][j] *= decay;
        }

        //Multiply the m_feerate_avg for the bucket j by the decay
        m_feerate_avg[j] *= decay;
        //Multiply the tansaction count average for the bucket j by decay
        txCtAvg[j] *= decay;
    }
}

//RANDY_COMMENTED
//BITCOIN_START
// returns -1 on error conditions
//BITCOIN_END
double TxConfirmStats::EstimateMedianVal(int confTarget, double sufficientTxVal,
                                         double successBreakPoint, unsigned int nBlockHeight,
                                         EstimationResult* result) const
{
    //BITCOIN_START
    // Counters for a bucket (or range of buckets)
    //BITCOIN_END

    //BITCOIN_START
    // Number of tx's confirmed within the confTarget
    //BITCOIN_END
    double nConf = 0;

    //BITCOIN_START
    // Total number of tx's that were ever confirmed
    //BITCOIN_END
    double totalNum = 0;

    //BITCOIN_START
    // Number of tx's still in mempool for confTarget or longer
    //BITCOIN_END

    //Assigned to 'inMempool' property of EstimatorBucket
    int extraNum = 0;

    //BITCOIN_START
    // Number of tx's that were never confirmed but removed from the mempool after confTarget
    //BITCOIN_END
    double failNum = 0;

    //The period target is the confTarget in the param, plus the scale minus 1, all over the scale.
    //I'm not sure what the '-1' does or what this is actually calculating
    // (confTarget - 1/scale )+ 1
    // Getting an interval from 0 to scale (how many above scale is it? At confTarget 0 it's 1/1 with slight shift of -1 to include 0 to scale all in first bucket)

    //Measuring how much over the scale we are
    const int periodTarget = (confTarget + scale - 1) / scale;

    //Gets the the max bucket index (last index of anything is always size - 1)
    const int maxbucketindex = buckets.size() - 1;

    //BITCOIN_START
    // We'll combine buckets until we have enough samples.
    // The near and far variables will define the range we've combined
    // The best variables are the last range we saw which still had a high
    // enough confirmation rate to count as success.
    // The cur variables are the current range we're counting.
    //BITCOIN_END

    //initialize all 'buckets' to max index

    //Set the current near bucket to the max index
    unsigned int curNearBucket = maxbucketindex;

    //Set the best near bucket to the max index
    unsigned int bestNearBucket = maxbucketindex;

    //Set cur far bucket to max index
    unsigned int curFarBucket = maxbucketindex;

    //Set the best far bucket to the max index
    unsigned int bestFarBucket = maxbucketindex;

    //Initialize foundAnswer to false
    bool foundAnswer = false;

    //Initialize bins to the unconfTx size (which should equal the max number of confirmation periods the 'unconfirmed' transactions have)
    unsigned int bins = unconfTxs.size();

    //Set that we're looking for a newBucketRange to true
    bool newBucketRange = true;

    //Initialize passing to true
    bool passing = true;

    //Create  2 estimator buckets, one for 'pass' and one for 'fail'
    EstimatorBucket passBucket;
    EstimatorBucket failBucket;


    // ^Initialized all curr and best bucket integer variables to maxIndex, made estitmator buckets, and some other random variables


    //BITCOIN_START
    // Start counting from highest feerate transactions
    //BITCOIN_END

    //for every bucket starting with the max index going to 0, where the maxbucketindex is equal to the last index in the 'buckets' variable passed in as the parameter

    //For every fee rate bucket in a period, calculate the total confirmed. For every feerate bucket (regardless of period) count the total. Count the number of failed for period and bucket.
    for (int bucket = maxbucketindex; bucket >= 0; --bucket) {

        //If the newBucketRange is true (our first iteration of loop?)
        //newBucketRange is only set to true if the currPct (current percentage) if curr range of buckets has sufficient number of txs AND is passing success breakpoint
        //Bucket range is recording the 'bucket range' of failing transactions until a succes thresh
        if (newBucketRange) {
            //Then set the curNearBucket to the bucket
            curNearBucket = bucket;

            //Set the newBucketRange to false
            newBucketRange = false;
        }

        //Set the curFar bucket to the current bucket
        curFarBucket = bucket;

        //Add the confAvg for (periodTarget -1) index and get ith bucket from period
        //Adds the bucket for the period in confAvg to nConf
        nConf += confAvg[periodTarget - 1][bucket];

        //Add the transaction count average at the index of 'bucket' to totalNum
        totalNum += txCtAvg[bucket];

        //Add the bucket's failAvg to failNum
        failNum += failAvg[periodTarget - 1][bucket];


        // ^Used every index of 'buckets' to calculate nConf, totalNum, and failNum values.


        //Calculate extraNum (number of transactions still in mempool for confTarget or higher)


        //For every confirmation number from the confirmation target to the max number of confirms
        for (unsigned int confct = confTarget; confct < GetMaxConfirms(); confct++)
            //Get the unconfirmed transactions for all buckets of confirmation, at the bucket index
            extraNum += unconfTxs[(nBlockHeight - confct) % bins][bucket];

        //Add the oldUnconfirmed transactions at the bucket index into extraNum
        extraNum += oldUnconfTxs[bucket];


        //BITCOIN_START
        // If we have enough transaction data points in this range of buckets,
        // we can test for success
        // (Only count the confirmed data points, so that each confirmation count
        // will be looking at the same amount of data and same bucket breaks)
        //BITCOIN_END


        //If the total amount of transactions is greather than sufficientTxVal expression threshold


        //If totalNum is greater than or equal to the sufficientTxVal parameter scaled by (1-decay)
        //more decay means a bigger tx threshold
        if (totalNum >= sufficientTxVal / (1 - decay)) {
            //Set the current percentage to nConf scaled by total
            double curPct = nConf / (totalNum + failNum + extraNum);

            //BITCOIN_START
            // Check to see if we are no longer getting confirmed at the success rate
            //BITCOIN_END


            //And if the percentage of all transacions that was confirmed within the confirmation target is less than successbreakpoint, then we initialize a failbucket and continue to next iteration


            //If current (percentage?) is less than the successBreakPoint
            if (curPct < successBreakPoint) {
                //And if passing is true
                if (passing == true) {
                    //BITCOIN_START
                    // First time we hit a failure record the failed bucket
                    //BITCOIN_END

                    //Get the index for a fail value for the min bucket
                    unsigned int failMinBucket = std::min(curNearBucket, curFarBucket);

                    //Get the index for a fail value for the max bucket
                    unsigned int failMaxBucket = std::max(curNearBucket, curFarBucket);


                    //Fail buckets only change the first time the totalNum count exceeds the threshold after a success. Failure isn't redefined again unless another success is hit.

                    //So we can infer fail end to start is the first time we got enough txs but it probably failed until 0 otherwise we would've got a new success

                    //If the failMinBucket is greater than 0 then define the start of the failBucket as the value at the failMinBucket index in buckets; otherwise set to 0
                    failBucket.start = failMinBucket ? buckets[failMinBucket - 1] : 0;

                    //The end of the failBucket is whatever value is at failBucket end
                    failBucket.end = buckets[failMaxBucket];

                    //The wihinTarget is set to nConf
                    failBucket.withinTarget = nConf;

                    //total confirmed is set to totalNum
                    failBucket.totalConfirmed = totalNum;

                    //In mempool is set to the extraNum
                    failBucket.inMempool = extraNum;

                    //The 'leftMempool' property is set to failNum
                    failBucket.leftMempool = failNum;

                    //Initialize passing to false
                    passing = false;
                }

                //BITCOIN_START
                //Continue
                ////BITCOIN_END
                //Unneeded continue
                continue;
            }
            //BITCOIN_START
            // Otherwise update the cumulative stats, and the bucket variables
            // and reset the counters
            //BITCOIN_END


            //If it was greater than the success threshold, initialize passBucket values


            //If the currentPct was greater than or equal to the success threshold
            else {
                //B_S
                // Reset any failed bucket, currently passing
                //B_E

                //set the fail bucket to a new estimator bucket
                failBucket = EstimatorBucket();

                //Set foundAnswer to 'true'
                foundAnswer = true;

                //Set passing to true
                passing = true;

                //Set the 'withinTarget' on the passBucket to nConf
                passBucket.withinTarget = nConf;

                //Reset nConf to 0
                nConf = 0;
                passBucket.totalConfirmed = totalNum;
                totalNum = 0;
                passBucket.inMempool = extraNum;
                passBucket.leftMempool = failNum;
                failNum = 0;
                extraNum = 0;

                //Best bucket is recorded here because we are successively going to less and less fee rate buckets
                //We're recording the greatest range of buckets for which we were successful at this confirmation level
                bestNearBucket = curNearBucket;
                bestFarBucket = curFarBucket;
                newBucketRange = true;
            }
        }
    }


    //Initialize the median to -1
    double median = -1;

    //Initialize txSum to 0
    double txSum = 0;

    //BITCOIN_START
    // Calculate the "average" feerate of the best bucket range that met success conditions
    // Find the bucket with the median transaction and then report the average feerate from that bucket
    // This is a compromise between finding the median which we can't since we don't save all tx's
    // and reporting the average which is less accurate
    //BITCOIN_END

    //Get the minimum of the 'best' buckets
    unsigned int minBucket = std::min(bestNearBucket, bestFarBucket);

    //Get the max of the 'best' buckets
    unsigned int maxBucket = std::max(bestNearBucket, bestFarBucket);

    //For every bucketindex value from minBucket to maxBucket
    for (unsigned int j = minBucket; j <= maxBucket; j++) {
        //Add the txCtAvg of that bucket to txSum
        txSum += txCtAvg[j];
    }

    //txSum here is the sum of all buckets in txCtAvg

    //If foundAnswer is true (the percentage of confirmed transactions out of all tracked transactions is greater than or equal to successBreakPoint) and the txSum is not 0
    if (foundAnswer && txSum != 0) {
        //Half txSum
        txSum = txSum / 2;

        //txSum here is half the sum of all buckets in txCtAvg (so the median value?)


        //For every bucket from min to max again
        for (unsigned int j = minBucket; j <= maxBucket; j++) {
            //If the txCtAvg at the bucket is less than the halfed txSum
            //if the number of transactions in feerate j is less than half the number of transactions
            if (txCtAvg[j] < txSum)
                //Subtract the value from txSum because we want to get the feerate j that contains the median number of txs
                txSum -= txCtAvg[j];

            //B_S
            // we're in the right bucket
            //B_END

            //Otherwise
            else {
                //m_feerate_avg[j] is the sum of all feerates in feerate bucket j multiplied by the decay whenever the moving avg was updated
                //txCtAvg is the total recorded txs for feerate bucket j
                //Set the median to m_feerate_avg at that bucket, over txCtAvg at the bucket
                median = m_feerate_avg[j] / txCtAvg[j];
                //And break
                break;
            }
        }

        //Make the pass bucket's start equal to one before the min bucket, 0 otherwise
        passBucket.start = minBucket ? buckets[minBucket - 1] : 0;
        //Make the pass bucket end equal to the max bucket
        passBucket.end = buckets[maxBucket];
    }

    //BITCOIN_START
    // If we were passing until we reached last few buckets with insufficient data, then report those as failed
    //BITCOIN_END

    //If the loop finished off passing and enough tx didn't pass sufficientTxVal to determine whether the curr bucket range would be passing
    if (passing && !newBucketRange) {
        //Use the buckets at the end of the loop (fewest confs) as failing
        unsigned int failMinBucket = std::min(curNearBucket, curFarBucket);
        unsigned int failMaxBucket = std::max(curNearBucket, curFarBucket);
        failBucket.start = failMinBucket ? buckets[failMinBucket - 1] : 0;
        failBucket.end = buckets[failMaxBucket];
        failBucket.withinTarget = nConf;
        failBucket.totalConfirmed = totalNum;
        failBucket.inMempool = extraNum;
        failBucket.leftMempool = failNum;
    }

    float passed_within_target_perc = 0.0;
    float failed_within_target_perc = 0.0;
    if ((passBucket.totalConfirmed + passBucket.inMempool + passBucket.leftMempool)) {
        passed_within_target_perc = 100 * passBucket.withinTarget / (passBucket.totalConfirmed + passBucket.inMempool + passBucket.leftMempool);
    }
    if ((failBucket.totalConfirmed + failBucket.inMempool + failBucket.leftMempool)) {
        failed_within_target_perc = 100 * failBucket.withinTarget / (failBucket.totalConfirmed + failBucket.inMempool + failBucket.leftMempool);
    }

    //log
    LogPrint(BCLog::ESTIMATEFEE, "FeeEst: %d > %.0f%% decay %.5f: feerate: %g from (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out) Fail: (%g - %g) %.2f%% %.1f/(%.1f %d mem %.1f out)\n",
             confTarget, 100.0 * successBreakPoint, decay,
             median, passBucket.start, passBucket.end,
             passed_within_target_perc,
             passBucket.withinTarget, passBucket.totalConfirmed, passBucket.inMempool, passBucket.leftMempool,
             failBucket.start, failBucket.end,
             failed_within_target_perc,
             failBucket.withinTarget, failBucket.totalConfirmed, failBucket.inMempool, failBucket.leftMempool);


    if (result) {
        //Define the pass bucket as the succeeding bucket range
        result->pass = passBucket;
        //Define the fail bucket as all not up to confirmation threshold
        result->fail = failBucket;
        //decay is set on instantiation of this txconfirmstats
        result->decay = decay;
        //scale is set on instantiation as well
        result->scale = scale;
    }

    //return the median val
    return median;
}

void TxConfirmStats::Write(AutoFile& fileout) const
{
    fileout << Using<EncodedDoubleFormatter>(decay);
    fileout << scale;
    fileout << Using<VectorFormatter<EncodedDoubleFormatter>>(m_feerate_avg);
    fileout << Using<VectorFormatter<EncodedDoubleFormatter>>(txCtAvg);
    fileout << Using<VectorFormatter<VectorFormatter<EncodedDoubleFormatter>>>(confAvg);
    fileout << Using<VectorFormatter<VectorFormatter<EncodedDoubleFormatter>>>(failAvg);
}

void TxConfirmStats::Read(AutoFile& filein, int nFileVersion, size_t numBuckets)
{
    // Read data file and do some very basic sanity checking
    // buckets and bucketMap are not updated yet, so don't access them
    // If there is a read failure, we'll just discard this entire object anyway
    size_t maxConfirms, maxPeriods;

    // The current version will store the decay with each individual TxConfirmStats and also keep a scale factor
    filein >> Using<EncodedDoubleFormatter>(decay);
    if (decay <= 0 || decay >= 1) {
        throw std::runtime_error("Corrupt estimates file. Decay must be between 0 and 1 (non-inclusive)");
    }
    filein >> scale;
    if (scale == 0) {
        throw std::runtime_error("Corrupt estimates file. Scale must be non-zero");
    }

    filein >> Using<VectorFormatter<EncodedDoubleFormatter>>(m_feerate_avg);
    if (m_feerate_avg.size() != numBuckets) {
        throw std::runtime_error("Corrupt estimates file. Mismatch in feerate average bucket count");
    }
    filein >> Using<VectorFormatter<EncodedDoubleFormatter>>(txCtAvg);
    if (txCtAvg.size() != numBuckets) {
        throw std::runtime_error("Corrupt estimates file. Mismatch in tx count bucket count");
    }
    filein >> Using<VectorFormatter<VectorFormatter<EncodedDoubleFormatter>>>(confAvg);
    maxPeriods = confAvg.size();
    maxConfirms = scale * maxPeriods;

    if (maxConfirms <= 0 || maxConfirms > 6 * 24 * 7) { // one week
        throw std::runtime_error("Corrupt estimates file.  Must maintain estimates for between 1 and 1008 (one week) confirms");
    }
    for (unsigned int i = 0; i < maxPeriods; i++) {
        if (confAvg[i].size() != numBuckets) {
            throw std::runtime_error("Corrupt estimates file. Mismatch in feerate conf average bucket count");
        }
    }

    filein >> Using<VectorFormatter<VectorFormatter<EncodedDoubleFormatter>>>(failAvg);
    if (maxPeriods != failAvg.size()) {
        throw std::runtime_error("Corrupt estimates file. Mismatch in confirms tracked for failures");
    }
    for (unsigned int i = 0; i < maxPeriods; i++) {
        if (failAvg[i].size() != numBuckets) {
            throw std::runtime_error("Corrupt estimates file. Mismatch in one of failure average bucket counts");
        }
    }

    // Resize the current block variables which aren't stored in the data file
    // to match the number of confirms and buckets
    resizeInMemoryCounters(numBuckets);

    LogPrint(BCLog::ESTIMATEFEE, "Reading estimates: %u buckets counting confirms up to %u blocks\n",
             numBuckets, maxConfirms);
}

//RANDY_COMMENTED
//Called from TxConfirmStats::ProcessTransaction
//Increments a value in unconfTxs corresponding to the blockindex (calculated from the blockHeight) and the bucketindex (calculated from the 'val' which is presumably the fee rate) and returns the bucketindex
unsigned int TxConfirmStats::NewTx(unsigned int nBlockHeight, double val)
{
    //get the bucketIndex it should belong to by looking up the first value that's greater than or equal to val
    unsigned int bucketindex = bucketMap.lower_bound(val)->second;

    //Gets the blockIndex the transaction should belong to by assigning it to an unconfTxs index derived from the blockheight
    //unconfTxs.size() = the size of the *first* dimension of the unconfTxs 2d vector. It represents how many possible confirmations there could be for current block recorded and processed?
    unsigned int blockIndex = nBlockHeight % unconfTxs.size();

    //Increment the unconfirmed transactions in that blockIndex and range (bucketIndex)
    unconfTxs[blockIndex][bucketindex]++;

    //return the range it got into
    return bucketindex;
}

//RANDY_COMMENTED
//Calculate the relative age ('blocksAgo') of the entry by doing nBestSeenHeight - entryHeight. If 'blocksAgo' spans more than the size of blocks covered by 'unconfTxs', then try and remove the transaction from 'oldUnconfTxs'. Otherwise remove one from unconfTxs from the value accessed using the blockIndex (calculated using the entry height) and the bucketindex passed in. If the 'inBlock' parameter is false and the blocksAgo is greater than the scale, increment the bucket index of 'failAvg' for every period until the entryHeight's.
void TxConfirmStats::removeTx(unsigned int entryHeight, unsigned int nBestSeenHeight, unsigned int bucketindex, bool inBlock)
{
    //BITCOIN_START
    //nBestSeenHeight is not updated yet for the new block
    //BITCOIN_END
    int blocksAgo = nBestSeenHeight - entryHeight;

    //BITCOIN_START
    // the BlockPolicyEstimator hasn't seen any blocks yet
    //BITCOIN_END

    //If the nBestSeenHeight is 0
    if (nBestSeenHeight == 0)
        //Change blocks ago to 0
        blocksAgo = 0;

    //If blocksAgo is less than 0 (meaning nBestSeenHeight wasn't defined but entry height is)
    if (blocksAgo < 0) {
        //SAy that we've encountered an error and return
        LogPrint(BCLog::ESTIMATEFEE, "Blockpolicy error, blocks ago is negative for mempool tx\n");

        //BITCOIN_START
        //This can't happen because we call this with our best seen height, no entries can have higher
        //BITCOIN_END
        return;
    }

    //If blocksAgo is greater than the size of unconfirmed transactions
    if (blocksAgo >= (int)unconfTxs.size()) {
        //If the unconfirmed transactions at the bucketindex to remove a transaction for is greater than 0
        if (oldUnconfTxs[bucketindex] > 0) {
            //remove one from the count
            oldUnconfTxs[bucketindex]--;
        } else {
            //Otherwise say it's already been removed since there's nothing to remove now
            LogPrint(BCLog::ESTIMATEFEE, "Blockpolicy error, mempool tx removed from >25 blocks,bucketIndex=%u already\n",
                     bucketindex);
        }
    } else {
        //Calculate the blockIndex which is the entryHeight modulo'd by unconfTxs
        //Why modulo?
        //modulo to get the bucket from the correct period
        //Things aren't calculated using blocks in unconfTxs, just periods
        unsigned int blockIndex = entryHeight % unconfTxs.size();

        //If the value at unconfTxs is greater than 0
        if (unconfTxs[blockIndex][bucketindex] > 0) {
            //remove one from the proper index
            unconfTxs[blockIndex][bucketindex]--;
        } else {
            //Otherwise say it was already removed
            LogPrint(BCLog::ESTIMATEFEE, "Blockpolicy error, mempool tx removed from blockIndex=%u,bucketIndex=%u already\n",
                     blockIndex, bucketindex);
        }
    }


    //BITCOIN_START
    // Only counts as a failure if not confirmed for entire period
    //BITCOIN_END

    //If inBlock is false and the  blockAge of the entryHeight relative to the best height is greater than 'scale'
    if (!inBlock && (unsigned int)blocksAgo >= scale) {
        //Make sure scale isn't 0
        assert(scale != 0);
        //Convert the blocksAgo to the period
        unsigned int periodsAgo = blocksAgo / scale;

        //For every period from 0 to the period this entry exists in
        for (size_t i = 0; i < periodsAgo && i < failAvg.size(); i++) {
            //increment the bucket index at that period in failAvg
            failAvg[i][bucketindex]++;
        }
    }
}

//BITCOIN_START
// This function is called from CTxMemPool::removeUnchecked to ensure
// txs removed from the mempool for any reason are no longer
// tracked. Txs that were part of a block have already been removed in
// processBlockTx to ensure they are never double tracked, but it is
// of no harm to try to remove them again.
//BITCOIN_END

//RANDY_COMMENTED
//Tries to delete the entry in mapMemPoolTxs with the parameter hash, and returns whether the hash mapped to a real transaction that could be deleted..
bool CBlockPolicyEstimator::removeTx(uint256 hash, bool inBlock)
{
    //Lock the fee estimator
    LOCK(m_cs_fee_estimator);
    return _removeTx(hash, inBlock);
}

bool CBlockPolicyEstimator::_removeTx(const uint256& hash, bool inBlock)
{
    AssertLockHeld(m_cs_fee_estimator);
    //Get the place in the hash-to-TxStatsInfo where the hash in the parameter is located
    std::map<uint256, TxStatsInfo>::iterator pos = mapMemPoolTxs.find(hash);

    //If the iterator is not at the end of the map
    if (pos != mapMemPoolTxs.end()) {
        //Remove the transaction from feeStats
        feeStats->removeTx(pos->second.blockHeight, nBestSeenHeight, pos->second.bucketIndex, inBlock);
        //remove transaction from short stats
        shortStats->removeTx(pos->second.blockHeight, nBestSeenHeight, pos->second.bucketIndex, inBlock);
        //remove transaction from longStats
        longStats->removeTx(pos->second.blockHeight, nBestSeenHeight, pos->second.bucketIndex, inBlock);
        //Erase the transaction from memPool map
        mapMemPoolTxs.erase(hash);
        return true;
    } else {
        //If the iterator is at the end (which means hash not found), return false because there's nothing to remove
        return false;
    }
}

//RANDY_COMMENTED (SUGGESTION: Make explicitly public)
//Constructor
//Initializes 'buckets' with the thresholds for each bucket, and initialized 'bucketMap' with (threshold,bucketIndexe) key values. fee_stats, long_stats, and short_stats are then initialized as pointers to TxConfirmStats which are initialized using the same bucket values but different constant values. The fee estimae file name is then attempted to be read and a log is made if the file can't be read (although I imagine it will be created later on which prevents any exception from being thrown, etc)
//ALL PROPERTIES ARE SET TO 0 BESIDES IMPORTANT ONES ABOVE
CBlockPolicyEstimator::CBlockPolicyEstimator(const fs::path& estimation_filepath)
    : m_estimation_filepath{estimation_filepath}, nBestSeenHeight{0}, firstRecordedHeight{0}, historicalFirst{0}, historicalBest{0}, trackedTxs{0}, untrackedTxs{0}
{
    //Assert that the MIN_BUCKET_FEERATE constant wasn't set to a non-positive number
    static_assert(MIN_BUCKET_FEERATE > 0, "Min feerate must be nonzero");

    //Intialize bucketIndex to 0
    size_t bucketIndex = 0;

    //for bucketBoundary starting at the minimum fee rate to going to max,incrementing boundary by fee spacing and incrementing the index based on min and max fee rate and spacing
    for (double bucketBoundary = MIN_BUCKET_FEERATE; bucketBoundary <= MAX_BUCKET_FEERATE; bucketBoundary *= FEE_SPACING, bucketIndex++) {
        //Push the bucket boundary value into 'buckets'
        buckets.push_back(bucketBoundary);
        //Also keep track of the index associated with that boundary value in bucketMap
        bucketMap[bucketBoundary] = bucketIndex;
    }

    //Push a large number to the back of the buckets vector
    buckets.push_back(INF_FEERATE);
    //This large number is also put in bucketMap and mapped to the index (which should be equal to the size -1 here)
    bucketMap[INF_FEERATE] = bucketIndex;
    //assert every value in buckets is in bucketMap as a key
    assert(bucketMap.size() == buckets.size());

    //Make a pointer to a new TxConfirmStats obj called feeStats with hard-coded constants for 'Medium' values?
    feeStats = std::unique_ptr<TxConfirmStats>(new TxConfirmStats(buckets, bucketMap, MED_BLOCK_PERIODS, MED_DECAY, MED_SCALE));

    //Make a pointer called shortStats that uses 'short' hard-coded constants in the TxConfirmStats construction
    shortStats = std::unique_ptr<TxConfirmStats>(new TxConfirmStats(buckets, bucketMap, SHORT_BLOCK_PERIODS, SHORT_DECAY, SHORT_SCALE));

    //ditto for longStats construction
    longStats = std::unique_ptr<TxConfirmStats>(new TxConfirmStats(buckets, bucketMap, LONG_BLOCK_PERIODS, LONG_DECAY, LONG_SCALE));

    //BITCOIN_START
    // If the fee estimation file is present, read recorded estimations
    //BITCOIN_END
    //Open the file as a binary file and place the file struct in the wrapper CAutoFile

    AutoFile est_file{fsbridge::fopen(m_estimation_filepath, "rb")};
    //If the file made is null or can't be read
    if (est_file.IsNull() || !Read(est_file)) {
        //log the failure
        LogPrintf("Failed to read fee estimates from %s. Continue anyway.\n", fs::PathToString(m_estimation_filepath));
    }
}

//RANDY_COMMENTED
//Just a declared destructor with no logic
CBlockPolicyEstimator::~CBlockPolicyEstimator() = default

//RANDY_COMMENTED
//*NOT* called from processBlockTx. Called directly from mempool (txmempool.cpp)
//If the transaction is not already in the CBlockPolicyEstimator's mapMemPoolTxs, is equal to the nBestSeenHeight, and the validFeeEstimate is true, then add the mempool entry into mapMemPoolTxs. The key is the entry transaction's hash and the properties that are initialized for the value in the mapMemPoolTxs entry is the height and the bucketindex calculated by 'NewTx' which is used to set the values of bucketindex2 and bucketindex3 all to the same thing as bucketindex.
void CBlockPolicyEstimator::processTransaction(const CTxMemPoolEntry& entry, bool validFeeEstimate)
{
    //Add a lock to the fee estimator
    LOCK(m_cs_fee_estimator);

    //Get the 'height' of the mempool entry in param
    unsigned int txHeight = entry.GetHeight();

    //Get the hash of the transaction in the mempool entry from param
    uint256 hash = entry.GetTx().GetHash();

    //If the hash is in our local mapMemPooltx
    if (mapMemPoolTxs.count(hash)) {
        //Log that we're already tacking this
        LogPrint(BCLog::ESTIMATEFEE, "Blockpolicy error mempool tx %s already being tracked\n",
                 hash.ToString());

        //and return
        return;
    }

    //If the transaction height is not equal to the best seen height
    if (txHeight != nBestSeenHeight) {
        //BITCOIN_START
        // Ignore side chains and re-orgs; assuming they are random they don't
        // affect the estimate.  We'll potentially double count transactions in 1-block reorgs.
        // Ignore txs if BlockPolicyEstimator is not in sync with ActiveChain().Tip().
        // It will be synced next time a block is processed.
        //BITCOIN_END

        //return
        return;
    }

    //BITCOIN_START
    // Only want to be updating estimates when our blockchain is synced,
    // otherwise we'll miscalculate how many blocks its taking to get included.
    //BITCOIN_END

    //If the validFeeEstimate bool in the parameter is false
    if (!validFeeEstimate) {
        //Increment untracked transactions (where an untracked transaction here seems to be something in the mempool with the best seen height, but not in the local mapMemPoolTxs)
        untrackedTxs++;
        //And return
        return;
    }

    //If the validFeeEstimate param is true, increment the tracked transactions
    trackedTxs++;

    //BITCOIN_START
    // Feerates are stored and reported as BTC-per-kb:
    //BITCOIN_END

    //Create a fee rate taken from the mempool entry's fee and given the size for context.
    CFeeRate feeRate(entry.GetFee(), entry.GetTxSize());

    //Put the mempool entry in mapMemPoolTxs by hash by declaring different properties on the value at that hash

    //Set the block height for the entry hash in mapMemPoolTxs to be the actual height saved on entry
    mapMemPoolTxs[hash].blockHeight = txHeight;

    //Create an integer bucketIndex equal to the return value of NewTx made from 'feeStats' that uses the transactionHeight and the fee rate per kilobyte (in SI interpretation of 1kb = 1000b). The return value is presumably the bucket index the new transaction should go into
    unsigned int bucketIndex = feeStats->NewTx(txHeight, (double)feeRate.GetFeePerK());

    //Set the bucketIndex for the entry hash in mapMemPoolTxs to the bucketIndex defined above
    mapMemPoolTxs[hash].bucketIndex = bucketIndex;

    //Set bucketIndex2 to the new transaction made from shortStats
    unsigned int bucketIndex2 = shortStats->NewTx(txHeight, (double)feeRate.GetFeePerK());

    //assert the bucketIndex is the same value as bucketIndex2
    assert(bucketIndex == bucketIndex2);

    //Set the bucketIndex3 to the bucketIndex returned from NewTx
    unsigned int bucketIndex3 = longStats->NewTx(txHeight, (double)feeRate.GetFeePerK());

    //assert that bucketIndex is the same value as bucketIndex3
    assert(bucketIndex == bucketIndex3);

    //All bucket indexes should equal the same thing as seen by assertions
}


//RANDY_COMMENTED
//**called from processBlock
//Get the difference in block height from the entry and the best seen and use that difference (called 'blocksToConfirm') to add the 'feerate' of that transaction (which contains the fee on the tx along with its size) to every feestats using 'Record'
//FALSE if transaction was never put in mempool txs OR if blcoksToConfirm shows we already processed block
bool CBlockPolicyEstimator::processBlockTx(unsigned int nBlockHeight, const CTxMemPoolEntry* entry)
{
    AssertLockHeld(m_cs_fee_estimator);

    //If we're not able to remove the transacton passed in as mempool entry
    if (!_removeTx(entry->GetTx().GetHash(), true)) {
        //B_START
        // This transaction wasn't being tracked for fee estimation
        //B_END

        //Return false
        return false;
    }

    //B_START
    // How many blocks did it take for miners to include this transaction?
    // blocksToConfirm is 1-based, so a transaction included in the earliest
    // possible block has confirmation count of 1
    //B_END

    //Get the blocksToConfirm by getting the difference between the block height recorded and the blockheight passed in from the entry
    int blocksToConfirm = nBlockHeight - entry->GetHeight();

    //If the blocksToConfirm is less than or equal to 0 (the tx is in an already processed block?)
    if (blocksToConfirm <= 0) {
        //B_START
        // This can't happen because we don't process transactions from a block with a height
        // lower than our greatest seen height
        //B_END

        //Log and return false
        LogPrint(BCLog::ESTIMATEFEE, "Blockpolicy error Transaction had negative blocksToConfirm\n");
        return false;
    }

    //B_START
    // Feerates are stored and reported as BTC-per-kb:
    //B_END

    //Create a new feeRate with the fee from the entry and a tx size from the entry
    CFeeRate feeRate(entry->GetFee(), entry->GetTxSize());

    //Record the fee rate in every one of the fee stats
    feeStats->Record(blocksToConfirm, (double)feeRate.GetFeePerK());
    shortStats->Record(blocksToConfirm, (double)feeRate.GetFeePerK());
    longStats->Record(blocksToConfirm, (double)feeRate.GetFeePerK());

    //reurn true
    return true;
}

//RANDY_COMMENTED
//Called from mempool just like processTransaction('minerPolicyEstimator->processBlock(nBlockHeight, entries);' in txmempool.cpp)
//Resets and adds the value of the 'old' unconf transaction counts onto oldUnconfTxs (with clearCurrent), decays confAvg and failAvg (with updateMovingAvg), processes block txs in mempool entries param (using method above 'processBlockTx'), sets 'firstRecordedHeight' (which should be set to first block processed), logs, and Sets tracked and untracked transactions to 0
void CBlockPolicyEstimator::processBlock(unsigned int nBlockHeight,
                                         std::vector<const CTxMemPoolEntry*>& entries)
{
    //Lock the estimator mutex
    LOCK(m_cs_fee_estimator);

    //If the blockheight isn't best, then return
    if (nBlockHeight <= nBestSeenHeight) {
        //B_START
        // Ignore side chains and re-orgs; assuming they are random
        // they don't affect the estimate.
        // And if an attacker can re-org the chain at will, then
        // you've got much bigger problems than "attacker can influence
        // transaction fees."
        //B_END
        return;
    }

    //B_START
    // Must update nBestSeenHeight in sync with ClearCurrent so that
    // calls to removeTx (via processBlockTx) correctly calculate age
    // of unconfirmed txs to remove from tracking.
    //B_END

    //Set the best height to current
    nBestSeenHeight = nBlockHeight;


    //B_START
    // Update unconfirmed circular buffer
    //B_END

    //Clear the uncornfirmed transaction count for every bucket in 'nBlockHeight's confirmation period
    feeStats->ClearCur rent(nBlockHeight);
    shortStats->ClearCurrent(nBlockHeight);
    longStats->ClearCurrent(nBlockHeight);

    //B_START
    // Decay all exponential averages
    //B_END

    //Delay every 2d index value of each feestat's confAvg and failAvg
    feeStats->UpdateMovingAverages();
    shortStats->UpdateMovingAverages();
    longStats->UpdateMovingAverages();

    //Set counted to 0. This is a count of all tx processed successfully
    unsigned int countedTxs = 0;

    //B_START
    // Update averages with data points from current block
    //B_END

    //go through every transaction
    for (const auto& entry : entries) {
        //If the block tx is processed successfully
        //Block entry would *not* be processed correctly if transaction was never put in mempool txs OR if blcoksToConfirm shows we already processed block
        if (processBlockTx(nBlockHeight, entry))
            //Add onto countedTx
            countedTxs++;
    }

    //If the firstRecordedHeight is 0 and we processed some transactions (this is our first time running fee estimation)
    if (firstRecordedHeight == 0 && countedTxs > 0) {
        //Reset the firstRecorded height to the best height (which should be set to the current block since this should only get hit once where there was a processed block)
        firstRecordedHeight = nBestSeenHeight;
        LogPrint(BCLog::ESTIMATEFEE, "Blockpolicy first recorded height %u\n", firstRecordedHeight);
    }


    LogPrint(BCLog::ESTIMATEFEE, "Blockpolicy estimates updated by %u of %u block txs, since last block %u of %u tracked, mempool map size %u, max target %u from %s\n",
             countedTxs, entries.size(), trackedTxs, trackedTxs + untrackedTxs, mapMemPoolTxs.size(),
             MaxUsableEstimate(), HistoricalBlockSpan() > BlockSpan() ? "historical" : "current");

    //Set tracked and untracked transactions to 0
    trackedTxs = 0;
    untrackedTxs = 0;
}

//RANDY_COMMENYED
//Calls estimateRawFee with validation on confTarget and hard-coded values for estimateRawfee
CFeeRate CBlockPolicyEstimator::estimateFee(int confTarget) const
{
    //B_START
    // It's not possible to get reasonable estimates for confTarget of 1
    //B_END

    //If the confirmation target is less than or equal to 1
    if (confTarget <= 1)
        //return a fee rate of 0 (since should be invalid)
        //Maybe log here?
        return CFeeRate(0);

    ///Gets the median val of the stats object chosen by the horizon, and returns it as the fee
    return estimateRawFee(confTarget, DOUBLE_SUCCESS_PCT, FeeEstimateHorizon::MED_HALFLIFE);
}


//RANDY_COMMENTED
//Called from: CBlockPolicyEstimator::estimateFee, RPCHelpMan::estimaterawfee
//Hardcoded to have successThreshold of ~95% (defiend in DOUBLE_SUCCESS_PCT const) and feeHorizon of 1 (from estmatesmartFee)
//Gets the median val of the stats object chosen by the horizon, and returns it as the fee
CFeeRate CBlockPolicyEstimator::estimateRawFee(int confTarget, double successThreshold, FeeEstimateHorizon horizon, EstimationResult* result) const
{
    //Set a tx stats pointer to null
    TxConfirmStats* stats = nullptr;

    //Set sufficientTxs to .1
    double sufficientTxs = SUFFICIENT_FEETXS;

    //switch horizon (which can only be 1 as of now unless set directly through rpc command 'estimateRawFee' that goes straight to this method)
    switch (horizon) {

    //if the halflife is short
    case FeeEstimateHorizon::SHORT_HALFLIFE: {
        //Get the short fee stats
        stats = shortStats.get();
        //Set sufficientTxs to whatever is appropriate
        sufficientTxs = SUFFICIENT_TXS_SHORT;
        break;
    }
    case FeeEstimateHorizon::MED_HALFLIFE: {
        //get the stats for feeStats
        stats = feeStats.get();
        break;
    }
    case FeeEstimateHorizon::LONG_HALFLIFE: {
        //get the stats for longStats
        stats = longStats.get();
        break;
    }
    }
    //B_START
    // no default case, so the compiler can warn about missing cases
    //B_END
    assert(stats);

    //lock the estimator
    LOCK(m_cs_fee_estimator);

    //B_START
    // Return failure if trying to analyze a target we're not tracking
    //B_END

    //If the confTarget is less than 0 (condition can only be hit using rpc), or if the confirmation target is outside our confirmationPeeriod then return a 0 feerate (invalid or in-error)
    if (confTarget <= 0 || (unsigned int)confTarget > stats->GetMaxConfirms())
        return CFeeRate(0);

    //If sucess threshold is greater than 1 then return 0 too because there can be no threshold better than 100%
    if (successThreshold > 1)
        return CFeeRate(0);

    //Get median val of chosen stats using the target and sufficientTx threshold and other stuff
    double median = stats->EstimateMedianVal(confTarget, sufficientTxs, successThreshold, nBestSeenHeight, result);

    //If the median is less than 0 then return invalid fee of 0
    if (median < 0)
        return CFeeRate(0);

    //If median is 0 or greater return it as the rate
    return CFeeRate(llround(median));
}

//RANDY_COMMENTED
//Returns the max confirms of the stats object corresponding to horizon in the param
unsigned int CBlockPolicyEstimator::HighestTargetTracked(FeeEstimateHorizon horizon) const
{
    //lock the fee estomator
    LOCK(m_cs_fee_estimator);
    //Swithc on the horizon param
    switch (horizon) {
    //If the horizon is short
    case FeeEstimateHorizon::SHORT_HALFLIFE: {
        //Return the max confirmations (confirmation periods) of short stats
        return shortStats->GetMaxConfirms();
    }
    //If the horizon is halflife
    case FeeEstimateHorizon::MED_HALFLIFE: {
        //Return max confirms of regular
        return feeStats->GetMaxConfirms();
    }
    //If long
    case FeeEstimateHorizon::LONG_HALFLIFE: {
        //Return max confirms of logn
        return longStats->GetMaxConfirms();
    }
    }
    //B_START
    // no default case, so the compiler can warn about missing cases
    //B_END
    assert(false);
}

//RANDY_COMMENTED
//Gets how many blocks has been processed by this blockpolicy since first recorded block
unsigned int CBlockPolicyEstimator::BlockSpan() const
{
    //if the first recorded height is 0 (we haven't processed a block yet), return 0
    if (firstRecordedHeight == 0) return 0;

    //Assert the best seen height is greater than or equal tot he first recorded
    assert(nBestSeenHeight >= firstRecordedHeight);

    //Return how many blocks we've seen since firstRecorded
    return nBestSeenHeight - firstRecordedHeight;
}

//RANDY_COMMENTED
//Returns the difference between hisotical best and first as long as diff between best seen and historical best isnt too great
unsigned int CBlockPolicyEstimator::HistoricalBlockSpan() const
{
    //historicalFirst seems to be set in ::Read. If it's 0, return 0
    if (historicalFirst == 0) return 0;


    assert(historicalBest >= historicalFirst);

    //If the nBestSeenHeight is too far away from historicalBest (OLDEST_ESTIMATE_HISTORY defining too far away), return 0
    if (nBestSeenHeight - historicalBest > OLDEST_ESTIMATE_HISTORY) return 0;

    //Return the difference in blocks of historicalBest and first
    return historicalBest - historicalFirst;
}

unsigned int CBlockPolicyEstimator::MaxUsableEstimate() const
{
    // Block spans are divided by 2 to make sure there are enough potential failing data points for the estimate
    return std::min(longStats->GetMaxConfirms(), std::max(BlockSpan(), HistoricalBlockSpan()) / 2);
}

/** Return a fee estimate at the required successThreshold from the shortest
 * time horizon which tracks confirmations up to the desired target.  If
 * checkShorterHorizon is requested, also allow short time horizon estimates
 * for a lower target to reduce the given answer */
double CBlockPolicyEstimator::estimateCombinedFee(unsigned int confTarget, double successThreshold, bool checkShorterHorizon, EstimationResult* result) const
{
    double estimate = -1;
    if (confTarget >= 1 && confTarget <= longStats->GetMaxConfirms()) {
        // Find estimate from shortest time horizon possible
        if (confTarget <= shortStats->GetMaxConfirms()) { // short horizon
            estimate = shortStats->EstimateMedianVal(confTarget, SUFFICIENT_TXS_SHORT, successThreshold, nBestSeenHeight, result);
        } else if (confTarget <= feeStats->GetMaxConfirms()) { // medium horizon
            estimate = feeStats->EstimateMedianVal(confTarget, SUFFICIENT_FEETXS, successThreshold, nBestSeenHeight, result);
        } else { // long horizon
            estimate = longStats->EstimateMedianVal(confTarget, SUFFICIENT_FEETXS, successThreshold, nBestSeenHeight, result);
        }
        if (checkShorterHorizon) {
            EstimationResult tempResult;
            // If a lower confTarget from a more recent horizon returns a lower answer use it.
            if (confTarget > feeStats->GetMaxConfirms()) {
                double medMax = feeStats->EstimateMedianVal(feeStats->GetMaxConfirms(), SUFFICIENT_FEETXS, successThreshold, nBestSeenHeight, &tempResult);
                if (medMax > 0 && (estimate == -1 || medMax < estimate)) {
                    estimate = medMax;
                    if (result) *result = tempResult;
                }
            }
            if (confTarget > shortStats->GetMaxConfirms()) {
                double shortMax = shortStats->EstimateMedianVal(shortStats->GetMaxConfirms(), SUFFICIENT_TXS_SHORT, successThreshold, nBestSeenHeight, &tempResult);
                if (shortMax > 0 && (estimate == -1 || shortMax < estimate)) {
                    estimate = shortMax;
                    if (result) *result = tempResult;
                }
            }
        }
    }
    return estimate;
}

/** Ensure that for a conservative estimate, the DOUBLE_SUCCESS_PCT is also met
 * at 2 * target for any longer time horizons.
 */
double CBlockPolicyEstimator::estimateConservativeFee(unsigned int doubleTarget, EstimationResult* result) const
{
    double estimate = -1;
    EstimationResult tempResult;
    if (doubleTarget <= shortStats->GetMaxConfirms()) {
        estimate = feeStats->EstimateMedianVal(doubleTarget, SUFFICIENT_FEETXS, DOUBLE_SUCCESS_PCT, nBestSeenHeight, result);
    }
    if (doubleTarget <= feeStats->GetMaxConfirms()) {
        double longEstimate = longStats->EstimateMedianVal(doubleTarget, SUFFICIENT_FEETXS, DOUBLE_SUCCESS_PCT, nBestSeenHeight, &tempResult);
        if (longEstimate > estimate) {
            estimate = longEstimate;
            if (result) *result = tempResult;
        }
    }
    return estimate;
}

/** estimateSmartFee returns the max of the feerates calculated with a 60%
 * threshold required at target / 2, an 85% threshold required at target and a
 * 95% threshold required at 2 * target.  Each calculation is performed at the
 * shortest time horizon which tracks the required target.  Conservative
 * estimates, however, required the 95% threshold at 2 * target be met for any
 * longer time horizons also.
 */
CFeeRate CBlockPolicyEstimator::estimateSmartFee(int confTarget, FeeCalculation* feeCalc, bool conservative) const
{
    LOCK(m_cs_fee_estimator);

    if (feeCalc) {
        feeCalc->desiredTarget = confTarget;
        feeCalc->returnedTarget = confTarget;
    }

    double median = -1;
    EstimationResult tempResult;

    // Return failure if trying to analyze a target we're not tracking
    if (confTarget <= 0 || (unsigned int)confTarget > longStats->GetMaxConfirms()) {
        return CFeeRate(0); // error condition
    }

    // It's not possible to get reasonable estimates for confTarget of 1
    if (confTarget == 1) confTarget = 2;

    unsigned int maxUsableEstimate = MaxUsableEstimate();
    if ((unsigned int)confTarget > maxUsableEstimate) {
        confTarget = maxUsableEstimate;
    }
    if (feeCalc) feeCalc->returnedTarget = confTarget;

    if (confTarget <= 1) return CFeeRate(0); // error condition

    assert(confTarget > 0); //estimateCombinedFee and estimateConservativeFee take unsigned ints
    /** true is passed to estimateCombined fee for target/2 and target so
     * that we check the max confirms for shorter time horizons as well.
     * This is necessary to preserve monotonically increasing estimates.
     * For non-conservative estimates we do the same thing for 2*target, but
     * for conservative estimates we want to skip these shorter horizons
     * checks for 2*target because we are taking the max over all time
     * horizons so we already have monotonically increasing estimates and
     * the purpose of conservative estimates is not to let short term
     * fluctuations lower our estimates by too much.
     */
    double halfEst = estimateCombinedFee(confTarget / 2, HALF_SUCCESS_PCT, true, &tempResult);
    if (feeCalc) {
        feeCalc->est = tempResult;
        feeCalc->reason = FeeReason::HALF_ESTIMATE;
    }
    median = halfEst;
    double actualEst = estimateCombinedFee(confTarget, SUCCESS_PCT, true, &tempResult);
    if (actualEst > median) {
        median = actualEst;
        if (feeCalc) {
            feeCalc->est = tempResult;
            feeCalc->reason = FeeReason::FULL_ESTIMATE;
        }
    }
    double doubleEst = estimateCombinedFee(2 * confTarget, DOUBLE_SUCCESS_PCT, !conservative, &tempResult);
    if (doubleEst > median) {
        median = doubleEst;
        if (feeCalc) {
            feeCalc->est = tempResult;
            feeCalc->reason = FeeReason::DOUBLE_ESTIMATE;
        }
    }

    if (conservative || median == -1) {
        double consEst = estimateConservativeFee(2 * confTarget, &tempResult);
        if (consEst > median) {
            median = consEst;
            if (feeCalc) {
                feeCalc->est = tempResult;
                feeCalc->reason = FeeReason::CONSERVATIVE;
            }
        }
    }

    if (median < 0) return CFeeRate(0); // error condition

    return CFeeRate(llround(median));
}

void CBlockPolicyEstimator::Flush()
{
    FlushUnconfirmed();

    AutoFile est_file{fsbridge::fopen(m_estimation_filepath, "wb")};
    if (est_file.IsNull() || !Write(est_file)) {
        LogPrintf("Failed to write fee estimates to %s. Continue anyway.\n", fs::PathToString(m_estimation_filepath));
    }
}

bool CBlockPolicyEstimator::Write(AutoFile& fileout) const
{
    try {
        LOCK(m_cs_fee_estimator);
        fileout << 149900;         // version required to read: 0.14.99 or later
        fileout << CLIENT_VERSION; // version that wrote the file
        fileout << nBestSeenHeight;
        if (BlockSpan() > HistoricalBlockSpan() / 2) {
            fileout << firstRecordedHeight << nBestSeenHeight;
        } else {
            fileout << historicalFirst << historicalBest;
        }
        fileout << Using<VectorFormatter<EncodedDoubleFormatter>>(buckets);
        feeStats->Write(fileout);
        shortStats->Write(fileout);
        longStats->Write(fileout);
    } catch (const std::exception&) {
        LogPrintf("CBlockPolicyEstimator::Write(): unable to write policy estimator data (non-fatal)\n");
        return false;
    }
    return true;
}

bool CBlockPolicyEstimator::Read(AutoFile& filein)
{
    try {
        LOCK(m_cs_fee_estimator);
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION) {
            throw std::runtime_error(strprintf("up-version (%d) fee estimate file", nVersionRequired));
        }

        // Read fee estimates file into temporary variables so existing data
        // structures aren't corrupted if there is an exception.
        unsigned int nFileBestSeenHeight;
        filein >> nFileBestSeenHeight;

        if (nVersionRequired < 149900) {
            LogPrintf("%s: incompatible old fee estimation data (non-fatal). Version: %d\n", __func__, nVersionRequired);
        } else { // New format introduced in 149900
            unsigned int nFileHistoricalFirst, nFileHistoricalBest;
            filein >> nFileHistoricalFirst >> nFileHistoricalBest;
            if (nFileHistoricalFirst > nFileHistoricalBest || nFileHistoricalBest > nFileBestSeenHeight) {
                throw std::runtime_error("Corrupt estimates file. Historical block range for estimates is invalid");
            }
            std::vector<double> fileBuckets;
            filein >> Using<VectorFormatter<EncodedDoubleFormatter>>(fileBuckets);
            size_t numBuckets = fileBuckets.size();
            if (numBuckets <= 1 || numBuckets > 1000) {
                throw std::runtime_error("Corrupt estimates file. Must have between 2 and 1000 feerate buckets");
            }

            std::unique_ptr<TxConfirmStats> fileFeeStats(new TxConfirmStats(buckets, bucketMap, MED_BLOCK_PERIODS, MED_DECAY, MED_SCALE));
            std::unique_ptr<TxConfirmStats> fileShortStats(new TxConfirmStats(buckets, bucketMap, SHORT_BLOCK_PERIODS, SHORT_DECAY, SHORT_SCALE));
            std::unique_ptr<TxConfirmStats> fileLongStats(new TxConfirmStats(buckets, bucketMap, LONG_BLOCK_PERIODS, LONG_DECAY, LONG_SCALE));
            fileFeeStats->Read(filein, nVersionThatWrote, numBuckets);
            fileShortStats->Read(filein, nVersionThatWrote, numBuckets);
            fileLongStats->Read(filein, nVersionThatWrote, numBuckets);

            // Fee estimates file parsed correctly
            // Copy buckets from file and refresh our bucketmap
            buckets = fileBuckets;
            bucketMap.clear();
            for (unsigned int i = 0; i < buckets.size(); i++) {
                bucketMap[buckets[i]] = i;
            }

            // Destroy old TxConfirmStats and point to new ones that already reference buckets and bucketMap
            feeStats = std::move(fileFeeStats);
            shortStats = std::move(fileShortStats);
            longStats = std::move(fileLongStats);

            nBestSeenHeight = nFileBestSeenHeight;
            historicalFirst = nFileHistoricalFirst;
            historicalBest = nFileHistoricalBest;
        }
    } catch (const std::exception& e) {
        LogPrintf("CBlockPolicyEstimator::Read(): unable to read policy estimator data (non-fatal): %s\n", e.what());
        return false;
    }
    return true;
}

void CBlockPolicyEstimator::FlushUnconfirmed()
{
    int64_t startclear = GetTimeMicros();
    LOCK(m_cs_fee_estimator);
    size_t num_entries = mapMemPoolTxs.size();
    // Remove every entry in mapMemPoolTxs
    while (!mapMemPoolTxs.empty()) {
        auto mi = mapMemPoolTxs.begin();
        _removeTx(mi->first, false); // this calls erase() on mapMemPoolTxs
    }
    int64_t endclear = GetTimeMicros();
    LogPrint(BCLog::ESTIMATEFEE, "Recorded %u unconfirmed txs from mempool in %gs\n", num_entries, (endclear - startclear) * 0.000001);
}

FeeFilterRounder::FeeFilterRounder(const CFeeRate& minIncrementalFee)
{
    CAmount minFeeLimit = std::max(CAmount(1), minIncrementalFee.GetFeePerK() / 2);
    feeset.insert(0);
    for (double bucketBoundary = minFeeLimit; bucketBoundary <= MAX_FILTER_FEERATE; bucketBoundary *= FEE_FILTER_SPACING) {
        feeset.insert(bucketBoundary);
    }
}

CAmount FeeFilterRounder::round(CAmount currentMinFee)
{
    std::set<double>::iterator it = feeset.lower_bound(currentMinFee);
    if ((it != feeset.begin() && insecure_rand.rand32() % 3 != 0) || it == feeset.end()) {
        it--;
    }
    return static_cast<CAmount>(*it);
}
