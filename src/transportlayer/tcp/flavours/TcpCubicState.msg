//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

import inet.common.INETDefs;
import inet.transportlayer.tcp.flavours.TcpTahoeRenoFamilyState;

namespace inet::tcp;

///
/// State variables for TcpCubic.
///
struct TcpCubicStateVariables extends TcpTahoeRenoFamilyStateVariables
{
   @descriptor(readonly);
   
   //turn on/off fast convergence
   int fast_convergence = 1;
   
   int max_increment = 16;
   
   //Constant multiplication decrease factor in Cubic algorithm. 
   int beta = 717;
   
   int bic_scale = 41;
   
    // turn on/off tcp friendliness
   int tcp_friendliness = 0;
   
   uint32_t cube_rtt_scale;
   uint32_t beta_scale;
   uint64_t cube_factor;
  
   uint32_t last_max_cwnd; // last maximum snd_cwnd (segments)
   uint32_t loss_cwnd; // Cwnd of first loss after slow start
   uint32_t	last_cwnd;	// the last snd_cwnd 
   uint32_t last_time;	// time when updated last_cwnd 
   uint32_t	bic_origin_point; //origin point of bic function 
   uint32_t bic_K;		// time to origin point from the beginning of the current epoch 
   uint32_t delay_min;	// min delay (msec << 3) 
   uint32_t epoch_start;// beginning of an epoch 
   uint32_t	ack_cnt;	// number of acks 
   uint32_t	tcp_cwnd;	// estimated tcp cwnd 
   
   bool isConcave = false;
   bool isFriendly = false;
   
   simtime_t lastJiffyTime;
   uint32 jiffyAcks = 0;
   uint32 jiffyDupacks = 0;
   simtime_t rtt = 0;
   
    
};

cplusplus(TcpCubicStateVariables) {{
  public:
    virtual std::string str() const override;
    virtual std::string detailedInfo() const override;
}}

