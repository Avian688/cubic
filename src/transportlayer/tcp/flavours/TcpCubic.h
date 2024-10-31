/*
 * TcpCubic.h
 *
 *  Created on: Nov 9, 2022
 *      Author: luca
 */

#ifndef CUBIC_TRANSPORTLAYER_TCP_FLAVOURS_TCPCUBIC_H_
#define CUBIC_TRANSPORTLAYER_TCP_FLAVOURS_TCPCUBIC_H_

#include <inet/transportlayer/tcp/TcpConnection.h>
#include "../../../../../tcpPaced/src/transportlayer/tcp/flavours/TcpPacedFamily.h"
#include "../../../../../tcpPaced/src/transportlayer/tcp/TcpPacedConnection.h"
#include "TcpCubicState_m.h"

#include <cmath>

#define BICTCP_BETA_SCALE    1024   /* Scale factor beta calculation
                     * max_cwnd = snd_cwnd * beta
                     */

#define BICTCP_HZ  10  /* BIC HZ 2^10 = 1024 */

#define BITS_PER_LONG 64

#define HZ 1000


namespace inet {
namespace tcp {

/**
 * Implements TCP Cubic.
 */

class INET_API TcpCubic: public TcpPacedFamily {
protected:
    TcpCubicStateVariables *&state; // alias to TcpAlgorithm's 'state'

    static simsignal_t bicTargetSignal;
    static simsignal_t originPointSignal;
    static simsignal_t cwndSegSignal;
    static simsignal_t bicKSignal;
    static simsignal_t cntSignal;
    static simsignal_t lastMaxWindowSignal;
    static simsignal_t delayMinSignal;
    static simsignal_t concaveSignal;
    static simsignal_t convexSignal;
    static simsignal_t friendlySignal;
    static simsignal_t recoveryPointSignal;
    static simsignal_t sndUnaSignal;

    /** Create and return a TcpNewRenoStateVariables object. */
    virtual TcpStateVariables* createStateVariables() override
    {
        return new TcpCubicStateVariables();
    }

    virtual void reset();
    uint32_t calculateCubicRoot(uint64_t number) ;
    virtual void updateCubicCwnd(uint32_t acked);
    virtual int32_t fls64(uint64_t x);
    virtual uint64_t __fls(uint64_t word);

public:
    /** Ctor */
    TcpCubic();

    /** Utility function to recalculate ssthresh */
    virtual void recalculateSlowStartThreshold();


    /** Redefine what should happen on retransmission */
    virtual void processRexmitTimer(TcpEventCode &event) override;

    /** Redefine what should happen when data got acked, to add congestion window management */
    virtual void receivedDataAck(uint32_t firstSeqAcked) override;

    /** Redefine what should happen when dupAck was received, to add congestion window management */
    virtual void receivedDuplicateAck() override;

    virtual void initialize() override;

    virtual void rttMeasurementComplete(simtime_t tSent, simtime_t tAcked) override;
};

} // namespace tcp
} // namespace inet

#endif /* INET_TRANSPORTLAYER_TCP_FLAVOURS_TCPCUBIC_H_ */
