/*
 * TcpCubic.cc
 *
 *  Created on: Nov 9, 2022
 *      Author: Luca Giacomoni
 */

#include "TcpCubic.h"

#include "inet/transportlayer/tcp/Tcp.h"

namespace inet {
namespace tcp {

#define DELAYED_ACK_TIMEOUT    0.2   // 200ms (RFC 1122: MUST be less than 0.5 seconds)
#define MAX_REXMIT_COUNT       12   // 12 retries
#define MIN_REXMIT_TIMEOUT     1.0   // 1s
//#define MIN_REXMIT_TIMEOUT    0.6   // 600ms (3 ticks)
#define MAX_REXMIT_TIMEOUT     240   // 2 * MSL (RFC 1122)
#define MIN_PERSIST_TIMEOUT    5   // 5s
#define MAX_PERSIST_TIMEOUT    60   // 60s

Register_Class(TcpCubic);

simsignal_t TcpCubic::bicTargetSignal = cComponent::registerSignal("bicTarget");
simsignal_t TcpCubic::originPointSignal = cComponent::registerSignal(
        "originalPoint");
simsignal_t TcpCubic::cwndSegSignal = cComponent::registerSignal("cwndSeg");
simsignal_t TcpCubic::bicKSignal = cComponent::registerSignal("bicK");
simsignal_t TcpCubic::cntSignal = cComponent::registerSignal("cnt");
simsignal_t TcpCubic::lastMaxWindowSignal = cComponent::registerSignal(
        "lastMaxWindow");
simsignal_t TcpCubic::delayMinSignal = cComponent::registerSignal("delayMin");
simsignal_t TcpCubic::concaveSignal = cComponent::registerSignal("concave");
simsignal_t TcpCubic::convexSignal = cComponent::registerSignal("convex");
simsignal_t TcpCubic::friendlySignal = cComponent::registerSignal("friendly");

simsignal_t TcpCubic::sndUnaSignal = cComponent::registerSignal("sndUna");
simsignal_t TcpCubic::recoveryPointSignal = cComponent::registerSignal("recoveryPoint");

TcpCubic::TcpCubic() :
        TcpTahoeRenoFamily(), state(
                (TcpCubicStateVariables*&) TcpAlgorithm::state) {
}

std::string TcpCubicStateVariables::str() const {
    std::stringstream out;
    out << TcpTahoeRenoFamilyStateVariables::str();
    return out.str();
}

std::string TcpCubicStateVariables::detailedInfo() const {
    std::stringstream out;
    out << TcpTahoeRenoFamilyStateVariables::detailedInfo();
    return out.str();
}

void TcpCubic::reset() {
    state->cnt = 0;
    state->last_max_cwnd = 0;
    state->loss_cwnd = 0;
    state->last_cwnd = 0;
    state->last_time = 0;
    state->bic_origin_point = 0;
    state->bic_K = 0;
    state->delay_min = 0;
    state->epoch_start = 0;
    state->ack_cnt = 0;
    state->tcp_cwnd = 0;

    conn->emit(cntSignal, state->cnt);
    conn->emit(lastMaxWindowSignal, state->last_max_cwnd);
    conn->emit(originPointSignal, state->bic_origin_point);
    conn->emit(bicKSignal, state->bic_K);
}

void TcpCubic::initialize() {
    TcpTahoeRenoFamily::initialize();
    reset();
    /* Precompute a bunch of the scaling factors that are used per-packet
     * based on SRTT of 100ms
     */

    state->beta_scale = 8 * (BICTCP_BETA_SCALE + state->beta) / 3
            / (BICTCP_BETA_SCALE - state->beta);

    state->cube_rtt_scale = (state->bic_scale << 3); /* 1024*c/rtt */

    /* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
     *  so K = cubic_root( (wmax-cwnd)*rtt/c )
     * the unit of K is bictcp_HZ=2^10, not HZ
     *
     *  c = bic_scale >> 10
     *  rtt = 100ms
     *
     * the following code has been designed and tested for
     * cwnd < 1 million packets
     * RTT < 100 seconds
     * HZ < 1,000,00  (corresponding to 10 nano-second)
     */

    /* 1/c * 2^2*bictcp_HZ * srtt */
    state->cube_factor = 1ull << (10 + 3 * BICTCP_HZ); /* 2^40 */

    /* divide by bic_scale and by constant Srtt (100ms) */
    state->cube_factor /= state->bic_scale * 10;

}

uint64_t TcpCubic::__fls(uint64_t word)
{
    int32_t num = BITS_PER_LONG - 1;

    if (!(word & (~0ul << 32))) {
        num -= 32;
        word <<= 32;
    }

    if (!(word & (~0ul << (BITS_PER_LONG-16)))) {
        num -= 16;
        word <<= 16;
    }
    if (!(word & (~0ul << (BITS_PER_LONG-8)))) {
        num -= 8;
        word <<= 8;
    }
    if (!(word & (~0ul << (BITS_PER_LONG-4)))) {
        num -= 4;
        word <<= 4;
    }
    if (!(word & (~0ul << (BITS_PER_LONG-2)))) {
        num -= 2;
        word <<= 2;
    }
    if (!(word & (~0ul << (BITS_PER_LONG-1))))
        num -= 1;
    return num;
}

int TcpCubic::fls64(uint64_t x)
{
    if (x == 0)
        return 0;
    return __fls(x) + 1;
}


uint32_t TcpCubic::calculateCubicRoot(uint64_t a) {
    uint32_t x, b, shift;
        /*
         * cbrt(x) MSB values for x MSB values in [0..63].
         * Precomputed then refined by hand - Willy Tarreau
         *
         * For x in [0..63],
         *   v = cbrt(x << 18) - 1
         *   cbrt(x) = (v[x] + 10) >> 6
         */
        static const uint8_t v[] = {
            /* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
            /* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
            /* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
            /* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
            /* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
            /* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
            /* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
            /* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
        };

        b = fls64(a);
        if (b < 7) {
            /* a in [0..63] */
            return ((uint32_t)v[(uint32_t)a] + 35) >> 6;
        }

        b = ((b * 84) >> 8) - 1;
        shift = (a >> (b * 3));

        x = ((uint32_t)(((uint32_t)v[shift] + 10) << b)) >> 6;

        /*
         * Newton-Raphson iteration
         *                         2
         * x    = ( 2 * x  +  a / x  ) / 3
         *  k+1          k         k
         */
        x = (2 * x + (uint32_t)(a /((uint64_t)x * (uint64_t)(x - 1))));
        x = ((x * 341) >> 10);
        return x;
}

void TcpCubic::updateCubicCwnd(uint32_t acked) {

    uint64_t offs, t;
    uint32_t delta, bic_target, max_cnt;

    uint32_t cwnd = state->snd_cwnd / state->snd_mss;

    //In the kernel code this is the number of jiffies.
    //The number of jiffies is incremented HZ times per second
    //tcp_time_stamp is in ms unit. The jiffy variable would match if HZ = 1000
    uint32_t tcp_time_stamp = simTime().inUnit(SIMTIME_MS);

    state->ack_cnt++; /* count the number of ACKs */

    if (state->last_cwnd == cwnd
            && (int32_t) (tcp_time_stamp - state->last_time) <= HZ / 32)
        return;


    if (!(state->epoch_start && tcp_time_stamp == state->last_time)) {

        state->last_cwnd = cwnd;
        state->last_time = tcp_time_stamp;

        if (state->epoch_start == 0) {
            state->epoch_start = tcp_time_stamp; /* record the beginning of an epoch */
            state->ack_cnt = 1; /* start counting */
            state->tcp_cwnd = cwnd; /* syn with cubic */

            if (state->last_max_cwnd <= cwnd) {
                state->bic_K = 0;
                state->bic_origin_point = cwnd;
            } else {
                /* Compute new K based on
                 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
                 */
                state->bic_K = calculateCubicRoot(
                        state->cube_factor * (state->last_max_cwnd - cwnd));
                state->bic_origin_point = state->last_max_cwnd;
            }
        }

        /* cubic function - calc*/
        /* calculate c * time^3 / rtt,
         *  while considering overflow in calculation of time^3
         * (so time^3 is done by using 64 bit)
         * and without the support of division of 64bit numbers
         * (so all divisions are done by using 32 bit)
         *  also NOTE the unit of those veriables
         *    time  = (t - K) / 2^bictcp_HZ
         *    c = bic_scale >> 10
         * rtt  = (srtt >> 3) / HZ
         * !!! The following code does not have overflow problems,
         * if the cwnd < 1 million packets !!!
         */

        t = (int32_t)(tcp_time_stamp - state->epoch_start);
        t += state->delay_min/1000;
        /* change the unit from HZ to bictcp_HZ */
        t <<= BICTCP_HZ;
        t /= HZ;

        if (t < state->bic_K) /* t - K */
            offs = state->bic_K - t;
        else
            offs = t - state->bic_K;

        /* c/rtt * (t-K)^3 */
        delta = (state->cube_rtt_scale * offs * offs * offs)
                >> (10 + 3 * BICTCP_HZ);
        if (t < state->bic_K) /* below origin*/
            bic_target = state->bic_origin_point - delta;
        else
            /* above origin*/
            bic_target = state->bic_origin_point + delta;

        /* cubic function - calc bictcp_cnt*/
        if (bic_target > cwnd) {
            state->cnt = cwnd / (bic_target - cwnd);
        } else {
            state->cnt = 100 * cwnd; /* very small increment*/
        }


        if (state->last_max_cwnd == 0 && state->cnt > 20)
            state->cnt = 20;
    }

    if (state->tcp_friendliness) {
            uint32_t scale = state->beta_scale;

            delta = (cwnd * scale) >> 3;
            while (state->ack_cnt > delta) {       /* update tcp cwnd */
                state->ack_cnt -= delta;
                state->tcp_cwnd++;
            }

            if (state->tcp_cwnd > cwnd) {  /* if bic is slower than tcp */
                delta = state->tcp_cwnd - cwnd;
                max_cnt = cwnd / delta;
                if (state->cnt > max_cnt)
                    state->cnt = max_cnt;
            }
    }
    state->cnt = std::max(state->cnt, 2U);

    conn->emit(cntSignal, state->cnt);
}

void TcpCubic::recalculateSlowStartThreshold() {

    state->epoch_start = 0; /* end of epoch */

    uint32_t cwnd = state->snd_cwnd / state->snd_mss;

    /* Wmax and fast convergence */
    if (cwnd <= state->last_max_cwnd && state->fast_convergence)
        state->last_max_cwnd = (cwnd * (BICTCP_BETA_SCALE + state->beta))
                / (2 * BICTCP_BETA_SCALE);
    else
        state->last_max_cwnd = cwnd;

    state->loss_cwnd = cwnd;

    state->ssthresh = uint32_t(
            std::max((cwnd * state->beta) / BICTCP_BETA_SCALE, 2U))
            * state->snd_mss;

    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(ssthreshSignal, state->ssthresh);
    conn->emit(lastMaxWindowSignal, state->last_max_cwnd);
    conn->emit(cwndSegSignal, cwnd);

}

void TcpCubic::processRexmitTimer(TcpEventCode &event) {
    TcpTahoeRenoFamily::processRexmitTimer(event);
//    RFC 5681:
//    On the other hand, when a TCP sender detects segment loss using the
//    retransmission timer and the given segment has already been
//    retransmitted by way of the retransmission timer at least once, the
//    value of ssthresh is held constant.
//    Furthermore, upon a timeout (as specified in [RFC2988]) cwnd MUST be
//    set to no more than the loss window, LW, which equals 1 full-sized
//    segment (regardless of the value of IW).

    std::cerr << "RTO at " << simTime() << std::endl;
    std::cerr << "cwnd=: " << state->snd_cwnd / state->snd_mss << ", in-flight="
            << (state->snd_max - state->snd_una) / state->snd_mss << std::endl;
    if (event == TCP_E_ABORT)
        return;

    reset();
    recalculateSlowStartThreshold();
    conn->emit(recoverSignal, state->recover);
    state->snd_cwnd = state->snd_mss;

    state->afterRto = true;
    conn->retransmitOneSegment(true);
    conn->emit(highRxtSignal, state->highRxt);

    conn->emit(cwndSignal, state->snd_cwnd);
    conn->emit(ssthreshSignal, state->ssthresh);
    conn->emit(cwndSegSignal, state->snd_cwnd / state->snd_mss);

}

void TcpCubic::receivedDataAck(uint32_t firstSeqAcked) {
    TcpTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    if (state->dupacks >= state->dupthresh) {
        //
        // Perform Fast Recovery: set cwnd to ssthresh (deflating the window).
        //
        EV_INFO << "Fast Recovery: setting cwnd to ssthresh=" << state->ssthresh << "\n";
        state->snd_cwnd = state->ssthresh;
        conn->emit(cwndSignal, state->snd_cwnd);
    }
    else{
        state->delay_min = state->srtt.inUnit(SIMTIME_US);
        if (state->snd_cwnd < state->ssthresh) {
            EV_INFO
                           << "cwnd <= ssthresh: Slow Start: increasing cwnd by one SMSS bytes to ";

            // perform Slow Start. RFC 2581: "During slow start, a TCP increments cwnd
            // by at most SMSS bytes for each ACK received that acknowledges new data."
            state->snd_cwnd += state->snd_mss;
            conn->emit(cwndSignal, state->snd_cwnd);
            conn->emit(ssthreshSignal, state->ssthresh);

            EV_INFO << "cwnd=" << state->snd_cwnd << "\n";
        } else {
            // perform Congestion Avoidance (RFC 2581)
            updateCubicCwnd(1);
            if (state->cwnd_cnt >= state->cnt) {
                state->snd_cwnd += state->snd_mss;
                state->cwnd_cnt = 0;

            } else {
                state->cwnd_cnt++;
            }


            conn->emit(cwndSignal, state->snd_cwnd);
            conn->emit(ssthreshSignal, state->ssthresh);


            EV_INFO
                           << "cwnd > ssthresh: Congestion Avoidance: increasing cwnd linearly, to "
                           << state->snd_cwnd << "\n";
        }
    }

    if(state->snd_cwnd > 0){
        //dynamic_cast<PacedTcpConnection*>(conn)->changeIntersendingTime(state->srtt.dbl()/((double) state->snd_cwnd/(double)state->snd_mss));
        dynamic_cast<PacedTcpConnection*>(conn)->changeIntersendingTime(0.000000001);
    }

    // Check if recovery phase has ended
    if (state->sack_enabled && state->lossRecovery) {
        // RFC 3517, page 7: "Once a TCP is in the loss recovery phase the following procedure MUST
        // be used for each arriving ACK:
        //
        // (A) An incoming cumulative ACK for a sequence number greater than
        // RecoveryPoint signals the end of loss recovery and the loss
        // recovery phase MUST be terminated.  Any information contained in
        // the scoreboard for sequence numbers greater than the new value of
        // HighACK SHOULD NOT be cleared when leaving the loss recovery
        // phase."
        if (seqGE(state->snd_una, state->recoveryPoint)) {
            EV_INFO << "Loss Recovery terminated.\n";
            state->lossRecovery = false;
            conn->emit(lossRecoverySignal, 0);
        }
        else{
            conn->setPipe();
            if (((int)state->snd_cwnd - (int)state->pipe) >= (int)state->snd_mss) // Note: Typecast needed to avoid prohibited transmissions
                conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
        }
        conn->emit(sndUnaSignal, state->snd_una);
        conn->emit(recoveryPointSignal, state->recoveryPoint);
    }

    sendData(false);
    conn->emit(cwndSegSignal, state->snd_cwnd / state->snd_mss);

}

void TcpCubic::receivedDuplicateAck() {
    TcpTahoeRenoFamily::receivedDuplicateAck();

    if (state->dupacks == state->dupthresh) {
        EV_INFO << "Reno on dupAcks == DUPTHRESH(=" << state->dupthresh << ": perform Fast Retransmit, and enter Fast Recovery:";

        if (state->sack_enabled) {
            // RFC 3517, page 6: "When a TCP sender receives the duplicate ACK corresponding to
            // DupThresh ACKs, the scoreboard MUST be updated with the new SACK
            // information (via Update ()).  If no previous loss event has occurred
            // on the connection or the cumulative acknowledgment point is beyond
            // the last value of RecoveryPoint, a loss recovery phase SHOULD be
            // initiated, per the fast retransmit algorithm outlined in [RFC2581].
            // The following steps MUST be taken:
            //
            // (1) RecoveryPoint = HighData
            //
            // When the TCP sender receives a cumulative ACK for this data octet
            // the loss recovery phase is terminated."

            // RFC 3517, page 8: "If an RTO occurs during loss recovery as specified in this document,
            // RecoveryPoint MUST be set to HighData.  Further, the new value of
            // RecoveryPoint MUST be preserved and the loss recovery algorithm
            // outlined in this document MUST be terminated.  In addition, a new
            // recovery phase (as described in section 5) MUST NOT be initiated
            // until HighACK is greater than or equal to the new value of
            // RecoveryPoint."
            if (state->recoveryPoint == 0 || seqGE(state->snd_una, state->recoveryPoint)) { // HighACK = snd_una
                state->recoveryPoint = state->snd_max; // HighData = snd_max
                state->lossRecovery = true;
                conn->emit(lossRecoverySignal, 1);
                EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
            }
        }
        // RFC 2581, page 5:
        // "After the fast retransmit algorithm sends what appears to be the
        // missing segment, the "fast recovery" algorithm governs the
        // transmission of new data until a non-duplicate ACK arrives.
        // (...) the TCP sender can continue to transmit new
        // segments (although transmission must continue using a reduced cwnd)."

        // enter Fast Recovery
        recalculateSlowStartThreshold();
        // "set cwnd to ssthresh plus 3 * SMSS." (RFC 2581)
        state->snd_cwnd = state->ssthresh + 3 * state->snd_mss; // 20051129 (1)
        conn->emit(cwndSignal, state->snd_cwnd);
        if(state->snd_cwnd > 0){
            //dynamic_cast<PacedTcpConnection*>(conn)->changeIntersendingTime(state->rtt.dbl()/((double) state->snd_cwnd/(double)state->snd_mss));
            dynamic_cast<PacedTcpConnection*>(conn)->changeIntersendingTime(0.000000001);
        }

        EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";

        // Fast Retransmission: retransmit missing segment without waiting
        // for the REXMIT timer to expire
        conn->retransmitOneSegment(false);

        // Do not restart REXMIT timer.
        // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
        // Resetting the REXMIT timer is discussed in RFC 2582/3782 (NewReno) and RFC 2988.

        if (state->sack_enabled) {
            // RFC 3517, page 7: "(4) Run SetPipe ()
            //
            // Set a "pipe" variable  to the number of outstanding octets
            // currently "in the pipe"; this is the data which has been sent by
            // the TCP sender but for which no cumulative or selective
            // acknowledgment has been received and the data has not been
            // determined to have been dropped in the network.  It is assumed
            // that the data is still traversing the network path."
            conn->setPipe();
            // RFC 3517, page 7: "(5) In order to take advantage of potential additional available
            // cwnd, proceed to step (C) below."
            if (state->lossRecovery) {
                // RFC 3517, page 9: "Therefore we give implementers the latitude to use the standard
                // [RFC2988] style RTO management or, optionally, a more careful variant
                // that re-arms the RTO timer on each retransmission that is sent during
                // recovery MAY be used.  This provides a more conservative timer than
                // specified in [RFC2988], and so may not always be an attractive
                // alternative.  However, in some cases it may prevent needless
                // retransmissions, go-back-N transmission and further reduction of the
                // congestion window."
                // Note: Restart of REXMIT timer on retransmission is not part of RFC 2581, however optional in RFC 3517 if sent during recovery.
                EV_INFO << "Retransmission sent during recovery, restarting REXMIT timer.\n";
                restartRexmitTimer();

                // RFC 3517, page 7: "(C) If cwnd - pipe >= 1 SMSS the sender SHOULD transmit one or more
                // segments as follows:"
                if (((int)state->snd_cwnd - (int)state->pipe) >= (int)state->snd_mss) // Note: Typecast needed to avoid prohibited transmissions
                    conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
            }
        }

        // try to transmit new segments (RFC 2581)
        sendData(false);
    }
    else if (state->dupacks > state->dupthresh) {
        //
        // Reno: For each additional duplicate ACK received, increment cwnd by SMSS.
        // This artificially inflates the congestion window in order to reflect the
        // additional segment that has left the network
        //
        state->snd_cwnd += state->snd_mss;
        if(state->snd_cwnd > 0){
            //dynamic_cast<PacedTcpConnection*>(conn)->changeIntersendingTime(state->srtt.dbl()/((double) state->snd_cwnd/(double)state->snd_mss));
            dynamic_cast<PacedTcpConnection*>(conn)->changeIntersendingTime(0.000000001);
        }
        EV_DETAIL << "Reno on dupAcks > DUPTHRESH(=" << state->dupthresh << ": Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";

        conn->emit(cwndSignal, state->snd_cwnd);

        // Note: Steps (A) - (C) of RFC 3517, page 7 ("Once a TCP is in the loss recovery phase the following procedure MUST be used for each arriving ACK")
        // should not be used here!

        // RFC 3517, pages 7 and 8: "5.1 Retransmission Timeouts
        // (...)
        // If there are segments missing from the receiver's buffer following
        // processing of the retransmitted segment, the corresponding ACK will
        // contain SACK information.  In this case, a TCP sender SHOULD use this
        // SACK information when determining what data should be sent in each
        // segment of the slow start.  The exact algorithm for this selection is
        // not specified in this document (specifically NextSeg () is
        // inappropriate during slow start after an RTO).  A relatively
        // straightforward approach to "filling in" the sequence space reported
        // as missing should be a reasonable approach."
        sendData(false);
    }
//      When a TCP sender receives the duplicate ACK corresponding to
//      DupThresh ACKs, the scoreboard MUST be updated with the new SACK
//      information (via Update ()).  If no previous loss event has occurred
//      on the connection or the cumulative acknowledgment point is beyond
//      the last value of RecoveryPoint, a loss recovery phase SHOULD be
//      initiated, per the fast retransmit algorithm outlined in [RFC2581].


//    if (state->dupacks >= state->dupthresh) {
//        if (!state->lossRecovery
//                && (state->recoveryPoint == 0
//                        || seqGE(state->snd_una, state->recoveryPoint))) {
//
//            state->recoveryPoint = state->snd_max; // HighData = snd_max
//            conn->emit(sndUnaSignal, state->snd_una);
//            conn->emit(recoveryPointSignal, state->recoveryPoint);
//            state->lossRecovery = true;
//            EV_DETAIL << " recoveryPoint=" << state->recoveryPoint;
//            conn->emit(lossRecoverySignal, 1);
//
//            // enter Fast Recovery
//            recalculateSlowStartThreshold();
//            // "set cwnd to ssthresh plus 3 * SMSS." (RFC 2581)
//            state->snd_cwnd = state->ssthresh + state->dupthresh * state->snd_mss;
//
//
//            conn->emit(cwndSignal, state->snd_cwnd);
//
//            EV_DETAIL << " set cwnd=" << state->snd_cwnd << ", ssthresh="
//                             << state->ssthresh << "\n";
//
//            // Fast Retransmission: retransmit missing segment without waiting
//            // for the REXMIT timer to expire
//            conn->retransmitOneSegment(false);
//            conn->emit(highRxtSignal, state->highRxt);
//        }
//
//
//        conn->emit(cwndSignal, state->snd_cwnd);
//        conn->emit(ssthreshSignal, state->ssthresh);
//
//    }
//
//    if(state->snd_cwnd > 0){
//        dynamic_cast<PacedTcpConnection*>(conn)->changeIntersendingTime(0.00000001);
//    }
//
//    if (state->lossRecovery) {
//        conn->setPipe();
//
//        if (((int) (state->snd_cwnd / state->snd_mss)
//                - (int) (state->pipe / (state->snd_mss))) >= 1) { // Note: Typecast needed to avoid prohibited transmissions
//            conn->sendDataDuringLossRecoveryPhase(state->snd_cwnd);
//        }
//        conn->emit(sndUnaSignal, state->snd_una);
//        conn->emit(recoveryPointSignal, state->recoveryPoint);
//    }
}

void TcpCubic::rttMeasurementComplete(simtime_t tSent, simtime_t tAcked)
{
    //
    // Jacobson's algorithm for estimating RTT and adaptively setting RTO.
    //
    // Note: this implementation calculates in doubles. An impl. which uses
    // 500ms ticks is available from old tcpmodule.cc:calcRetransTimer().
    //

    // update smoothed RTT estimate (srtt) and variance (rttvar)
    const double g = 0.125; // 1 / 8; (1 - alpha) where alpha == 7 / 8;
    simtime_t newRTT = tAcked - tSent;
    state->rtt = newRTT;

    simtime_t& srtt = state->srtt;
    simtime_t& rttvar = state->rttvar;

    simtime_t err = newRTT - srtt;

    srtt += g * err;
    rttvar += g * (fabs(err) - rttvar);

    // assign RTO (here: rexmit_timeout) a new value
    simtime_t rto = srtt + 4 * rttvar;

    if (rto > MAX_REXMIT_TIMEOUT)
        rto = MAX_REXMIT_TIMEOUT;
    else if (rto < MIN_REXMIT_TIMEOUT)
        rto = MIN_REXMIT_TIMEOUT;

    state->rexmit_timeout = rto;

    // record statistics
    EV_DETAIL << "Measured RTT=" << (newRTT * 1000) << "ms, updated SRTT=" << (srtt * 1000)
              << "ms, new RTO=" << (rto * 1000) << "ms\n";

    conn->emit(rttSignal, newRTT);
    conn->emit(srttSignal, srtt);
    conn->emit(rttvarSignal, rttvar);
    conn->emit(rtoSignal, rto);
}

} //tcp
} //inet
