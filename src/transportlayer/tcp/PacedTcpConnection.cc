//
// Copyright (C) 2020 Luca Giacomoni and George Parisis
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "PacedTcpConnection.h"
namespace inet {
namespace tcp {

Define_Module(PacedTcpConnection);

PacedTcpConnection::PacedTcpConnection()
{

}

PacedTcpConnection::~PacedTcpConnection()
{
    cancelEvent(paceMsg);
    delete paceMsg;
}


bool PacedTcpConnection::processTimer(cMessage *msg)
{
    printConnBrief();
    EV_DETAIL << msg->getName() << " timer expired\n";

    // first do actions
    TcpEventCode event;
    
    if (msg == paceMsg) {
        processPaceTimer();
    }

    else if (msg == the2MSLTimer) {
        event = TCP_E_TIMEOUT_2MSL;
        process_TIMEOUT_2MSL();
    }
    else if (msg == connEstabTimer) {
        event = TCP_E_TIMEOUT_CONN_ESTAB;
        process_TIMEOUT_CONN_ESTAB();
    }
    else if (msg == finWait2Timer) {
        event = TCP_E_TIMEOUT_FIN_WAIT_2;
        process_TIMEOUT_FIN_WAIT_2();
    }
    else if (msg == synRexmitTimer) {
        event = TCP_E_IGNORE;
        process_TIMEOUT_SYN_REXMIT(event);
    }
    else {
        event = TCP_E_IGNORE;
        tcpAlgorithm->processTimer(msg, event);
    }

    // then state transitions
    return performStateTransition(event);
}



void PacedTcpConnection::initConnection(TcpOpenCommand *openCmd)
{
    TcpConnection::initConnection(openCmd);

    paceMsg = new cMessage("pacing message");

    intersendingTime = 0.0000001;
    pace = true;
    paceValueVec.setName("paceValue");
    bufferedPacketsVec.setName("bufferedPackets");

}

void PacedTcpConnection::initClonedConnection(TcpConnection *listenerConn)
{
    paceMsg = new cMessage("pacing message");
    intersendingTime = 0.00001;
    paceValueVec.setName("paceValue");
    bufferedPacketsVec.setName("bufferedPackets");
    pace = false;
    TcpConnection::initClonedConnection(listenerConn);
}

void PacedTcpConnection::addPacket(Packet *packet)
{
    Enter_Method("addPacket");
    if (packetQueue.empty()) {
        if (intersendingTime != 0){
            paceStart = simTime();
            scheduleAt(simTime() + intersendingTime, paceMsg);
        }
        else {
            paceStart = simTime();
            scheduleAt(simTime() + 0.000001, paceMsg);
        }
    }

    packetQueue.push(packet);
}

void PacedTcpConnection::processPaceTimer()
{
    Enter_Method("ProcessPaceTimer");

    tcpMain->sendFromConn(packetQueue.front(), "ipOut");

    packetQueue.pop();
    bufferedPacketsVec.record(packetQueue.size());

    if (!packetQueue.empty()) {
//        if (intersendingTime != 0)
            scheduleAt(simTime() + intersendingTime, paceMsg);
//        else
//            throw cRuntimeError("Pace is not set.");
    }

}

void PacedTcpConnection::sendToIP(Packet *tcpSegment, const Ptr<TcpHeader> &tcpHeader)
{ 
    
    // record seq (only if we do send data) and ackno
    if (tcpSegment->getByteLength() > B(tcpHeader->getChunkLength()).get())
        emit(sndNxtSignal, tcpHeader->getSequenceNo());

    emit(sndAckSignal, tcpHeader->getAckNo());

    // final touches on the segment before sending
    tcpHeader->setSrcPort(localPort);
    tcpHeader->setDestPort(remotePort);
    ASSERT(tcpHeader->getHeaderLength() >= TCP_MIN_HEADER_LENGTH);
    ASSERT(tcpHeader->getHeaderLength() <= TCP_MAX_HEADER_LENGTH);
    ASSERT(tcpHeader->getChunkLength() == tcpHeader->getHeaderLength());

    EV_INFO << "Sending: ";
    printSegmentBrief(tcpSegment, tcpHeader);

    // TODO reuse next function for sending

    const IL3AddressType *addressType = remoteAddr.getAddressType();
    tcpSegment->addTagIfAbsent<DispatchProtocolReq>()->setProtocol(addressType->getNetworkProtocol());

    if (ttl != -1 && tcpSegment->findTag<HopLimitReq>() == nullptr)
        tcpSegment->addTag<HopLimitReq>()->setHopLimit(ttl);

    if (dscp != -1 && tcpSegment->findTag<DscpReq>() == nullptr)
        tcpSegment->addTag<DscpReq>()->setDifferentiatedServicesCodePoint(dscp);

    if (tos != -1 && tcpSegment->findTag<TosReq>() == nullptr)
        tcpSegment->addTag<TosReq>()->setTos(tos);

    auto addresses = tcpSegment->addTagIfAbsent<L3AddressReq>();
    addresses->setSrcAddress(localAddr);
    addresses->setDestAddress(remoteAddr);

    // ECN:
    // We decided to use ECT(1) to indicate ECN capable transport.
    //
    // rfc-3168, page 6:
    // Routers treat the ECT(0) and ECT(1) codepoints
    // as equivalent.  Senders are free to use either the ECT(0) or the
    // ECT(1) codepoint to indicate ECT.
    //
    // rfc-3168, page 20:
    // For the current generation of TCP congestion control algorithms, pure
    // acknowledgement packets (e.g., packets that do not contain any
    // accompanying data) MUST be sent with the not-ECT codepoint.
    //
    // rfc-3168, page 20:
    // ECN-capable TCP implementations MUST NOT set either ECT codepoint
    // (ECT(0) or ECT(1)) in the IP header for retransmitted data packets
    tcpSegment->addTagIfAbsent<EcnReq>()->setExplicitCongestionNotification((state->ect && !state->sndAck && !state->rexmit) ? IP_ECN_ECT_1 : IP_ECN_NOT_ECT);

    tcpHeader->setCrc(0);
    tcpHeader->setCrcMode(tcpMain->crcMode);

    insertTransportProtocolHeader(tcpSegment, Protocol::tcp, tcpHeader);

    if(pace){
        addPacket(tcpSegment);
        bufferedPacketsVec.record(packetQueue.size());
    }
    else{
//        tcpSegment = addSkbInfoTags(tcpSegment);
        tcpMain->sendFromConn(tcpSegment, "ipOut");
    }
    bufferedPacketsVec.record(packetQueue.size());

}

void PacedTcpConnection::changeIntersendingTime(simtime_t _intersendingTime)
{
    ASSERT(_intersendingTime > 0);
    intersendingTime = _intersendingTime;
    EV_TRACE << "New pace: " << intersendingTime << "s" << std::endl;
    //std::cout << "New pace: " << intersendingTime << "s" << std::endl;
    paceValueVec.record(intersendingTime);
    if (paceMsg->isScheduled()) {
        simtime_t newArrivalTime = paceStart + intersendingTime;
        if (newArrivalTime < simTime()) {
            paceStart = simTime();
            rescheduleAt(simTime(), paceMsg);
        }
        else {
            paceStart = simTime();
            rescheduleAt(newArrivalTime, paceMsg);
        }
    }
}

void PacedTcpConnection::setPipe() {
    ASSERT(state->sack_enabled);

    // RFC 3517, pages 1 and 2: "
    // "HighACK" is the sequence number of the highest byte of data that
    // has been cumulatively ACKed at a given point.
    //
    // "HighData" is the highest sequence number transmitted at a given
    // point.
    //
    // "HighRxt" is the highest sequence number which has been
    // retransmitted during the current loss recovery phase.
    //
    // "Pipe" is a sender's estimate of the number of bytes outstanding
    // in the network.  This is used during recovery for limiting the
    // sender's sending rate.  The pipe variable allows TCP to use a
    // fundamentally different congestion control than specified in
    // [RFC2581].  The algorithm is often referred to as the "pipe
    // algorithm"."
    // HighAck = snd_una
    // HighData = snd_max

    state->highRxt = rexmitQueue->getHighestRexmittedSeqNum();
    state->pipe = 0;
    uint32_t length = 0; // required for rexmitQueue->checkSackBlock()
    bool sacked; // required for rexmitQueue->checkSackBlock()
    bool rexmitted; // required for rexmitQueue->checkSackBlock()

    // RFC 3517, page 3: "This routine traverses the sequence space from HighACK to HighData
    // and MUST set the "pipe" variable to an estimate of the number of
    // octets that are currently in transit between the TCP sender and
    // the TCP receiver.  After initializing pipe to zero the following
    // steps are taken for each octet 'S1' in the sequence space between
    // HighACK and HighData that has not been SACKed:"
    for (uint32_t s1 = state->snd_una; seqLess(s1, state->snd_max); s1 +=
            length) {
        rexmitQueue->checkSackBlock(s1, length, sacked, rexmitted);

        if (!sacked) {
            // RFC 3517, page 3: "(a) If IsLost (S1) returns false:
            //
            //     Pipe is incremented by 1 octet.
            //
            //     The effect of this condition is that pipe is incremented for
            //     packets that have not been SACKed and have not been determined
            //     to have been lost (i.e., those segments that are still assumed
            //     to be in the network)."
            if (isLost(s1) == false)
                state->pipe += length;

            // RFC 3517, pages 3 and 4: "(b) If S1 <= HighRxt:
            //
            //     Pipe is incremented by 1 octet.
            //
            //     The effect of this condition is that pipe is incremented for
            //     the retransmission of the octet.
            //
            //  Note that octets retransmitted without being considered lost are
            //  counted twice by the above mechanism."
            if (seqLess(s1, state->highRxt))
                state->pipe += length;
        }
    }
    state->pipe = state->pipe - (packetQueue.size()*state->snd_mss);
    emit(pipeSignal, state->pipe);
}
}}
