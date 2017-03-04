// -----------------------------------------------------------------
// Tssh - A ssh test client. 
// Copyright (C) 2016  Gabriele Bonacini
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
// -----------------------------------------------------------------

#include <Tssh.hpp>

namespace tssh{
   using  std::string;
   using  std::vector;
   using  std::initializer_list;
   using  std::tuple;
   using  std::to_string;
   using  std::fill;
   using  std::equal;
   using  std::cerr;
   using  std::cin;
   using  std::cout;
   using  std::endl;
   using  std::get;

   using  stringutils::addVarLengthDataCCharStr;
   using  stringutils::addVarLengthDataString;
   using  stringutils::appendVectBuffer;
   using  stringutils::charToUint32;
   using  stringutils::decodeB64;
   using  stringutils::encodeB64;
   using  stringutils::getPassword;
   using  stringutils::getVariableLengthRawValue;
   using  stringutils::getVariableLengthSingleBignum;
   using  stringutils::getVariableLengthValueCsv;
   using  stringutils::insArrayVals;
   using  stringutils::loadFileMem;
   using  stringutils::secureZeroing;
   using  stringutils::trace;
   using  stringutils::getDebug;
   using  stringutils::uint32ToUChars;
   using  stringutils::StringUtilsException;

   using  typeutils::safePtrdiff;
   using  typeutils::safeUint32;
   using  typeutils::safeSizeT;
   using  typeutils::safeInt;
   using  typeutils::safeUInt;
   using  typeutils::safeULong;
   using  typeutils::safeSizeT;

   using  inet::InetException;

   using  crypto::Crypto;

   static const char INITIAL_IV_C_TO_S                = 'A';
   static const char INITIAL_IV_S_TO_C                = 'B';
   static const char ENCR_KEY_C_TO_S                  = 'C';
   static const char ENCR_KEY_S_TO_C                  = 'D';
   static const char INTEGRITY_KEY_C_TO_S             = 'E';
   static const char INTEGRITY_KEY_S_TO_C             = 'F';
   
   static const char *SSH_CONF_DIRECTORY              = ".ssh";
   static const char *SSH_KNOWN_HOST_FILE             = "known_hosts";
   static const char *SSH_DEFAULT_TERM                = "vt100";
   static const char *SSH_PTY_REQ                     = "pty-req";
   static const char *SSH_SHELL_REQ                   = "shell";
   
   static const char *SSH_ID_STRING                   = "SSH-2.0-bg\r\n";
   static const char *SSH_HEADER_ID                   = "SSH-2.0";
   static const char *RAND_FILE                       = "/dev/urandom";
   
   static const char *SSH_USERAUTH_STRING             = "ssh-userauth";
   static const char *SSH_CONNECT_STRING              = "ssh-connection";
   static const char *SSH_PUBKEY_AUTH_REQ             = "publickey";
   static const char *SSH_PASSWD_SPEC                 = "password";
   static const char *SSH_KEYB_INTER_SPEC             = "keyboard-interactive";
   static const char *SSH_SESSION_SPEC                = "session";
   static const char *SSH_WNDW_RESIZE                 = "window-change";

   VarData::~VarData(void){}

   VarDataBin::VarDataBin(vector<uint8_t>& val) : data(val){}
   
   void VarDataBin::appendData(vector<uint8_t>& dest) noexcept(false){
         try{
            dest.insert(dest.end(), data.begin(), data.end());
         }catch(...){
            throw(InetException("appendData : a : Data Error."));
         }
   }
   
   size_t VarDataBin::size(void)  noexcept(true){
         return data.size();
   }
   
   VarDataChar::VarDataChar(char val) : data(val){}
   
   void VarDataChar::appendData(vector<uint8_t>& dest) noexcept(false){
         try{
            dest.push_back(static_cast<uint8_t>(data));
         }catch(...){
            throw(InetException("appendData : b : Data Error."));
         }
   }
   
   size_t VarDataChar::size(void)  noexcept(true){
         return sizeof(uint8_t);
   }
   
   VarDataUint32::VarDataUint32(uint32_t val) : data(val){}
   
   void VarDataUint32::appendData(vector<uint8_t>& dest)  noexcept(false){
         uint32ToUChars(dest, data);
   }
   
   size_t VarDataUint32::size(void)  noexcept(true){
         return sizeof(uint32_t);
   }
   
   template<class T>
   VarDataString<T>::VarDataString(T& val) : data(val){}
   
   template<class T>
   void VarDataString<T>::appendData(vector<uint8_t>& dest)  noexcept(false){
         addVarLengthDataString(data, dest);
   }
   
   template<class T>
   size_t VarDataString<T>::size(void)  noexcept(true){
         return data.size();
   }
   
   VarDataCharArr::VarDataCharArr(const char* val) : data(val){}
   
   VarDataCharArr::~VarDataCharArr(void){}
   
   void VarDataCharArr::appendData(vector<uint8_t>& dest)  noexcept(false){
         addVarLengthDataCCharStr(data, dest);
   }
   
   size_t VarDataCharArr::size(void)  noexcept(true){
         return strlen(data);
   }
   
   VarDataRecursive::VarDataRecursive(initializer_list<VarData*>&& sList) : subList(move(sList)), globalSize(0){}
   
   VarDataRecursive::~VarDataRecursive(void){}
   
   void VarDataRecursive::appendData(vector<uint8_t>& dest)  noexcept(false){
         uint32ToUChars(dest, 0);
         for(auto elem : subList) {
            addSize(elem->size());
            elem->appendData(dest);
            delete elem;
         }

         #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
         #pragma clang diagnostic push
         #pragma clang diagnostic ignored "-Wundefined-func-template"
         #endif

         uint32ToUChars(&(*(dest.end() - safePtrdiff(globalSize + sizeof(uint32_t)))), 
                        safeUint32(globalSize));

         #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
         #pragma clang diagnostic pop
         #endif
   }
   
   size_t VarDataRecursive::size(void)  noexcept(true){
         return globalSize;
   }
   
   void VarDataRecursive::addSize(size_t len)  noexcept(true){
         globalSize += len + sizeof(uint32_t);
   }

   VarDataIn::~VarDataIn(){}

   template<class T>
   VarDataBlob<T>::VarDataBlob(T& dest, string dsc) : data(dest), descr(dsc){}
   
   template<class T>
   size_t VarDataBlob<T>::insertData(vector<uint8_t>& buff, size_t offset)  noexcept(false){
         TRACE(" \n  ** " + descr + ":\n", &buff, offset, 
               sizeof(uint32_t) + offset + charToUint32(buff.data() + offset) ); 
         return getVariableLengthRawValue(buff, offset, data);
   }

   VarDataBNum::VarDataBNum(BIGNUM* dest, string dsc) : data(dest), descr(dsc){}
   
   size_t VarDataBNum::insertData(vector<uint8_t>& buff, size_t offset)  noexcept(false){
         TRACE(" \n  ** " + descr + ":\n", &buff, offset,
               sizeof(uint32_t) + offset + charToUint32(buff.data() + offset) ); 
         return getVariableLengthSingleBignum(buff, offset, data);
   }

   #if defined  __clang_major__ && !defined __APPLE__ && __clang_major__ >= 4
   #pragma clang diagnostic push
   #pragma clang diagnostic ignored "-Wundefined-func-template"
   #endif

   SshTransport::SshTransport(string host, string port): 
                 InetClient(host.c_str(), port.c_str()), hostname(host), 
                 clientIdString(SSH_ID_STRING), haveKeys(false){ 
  
      rndFd =  open(RAND_FILE, O_RDONLY);
      if(rndFd == -1)
         throw(InetException("SshTransport: Can't open random generator."));
   
      packetsRcvCount = std::numeric_limits<uint32_t>::max();   
      packetsSndCount = std::numeric_limits<uint32_t>::max();

      initBuffer(SSH_MAX_PACKET_SIZE);
      try{
         incomingEnc.resize(SSH_MAX_PACKET_SIZE * 10);  
         outcomingEnc.resize(SSH_MAX_PACKET_SIZE);
         currentHashS.resize(SSH_MAX_PACKET_SIZE);
         keys.resize(SSH_STD_KEYS_NUMBER);
         message.resize(SSH_MAX_PACKET_SIZE);
         partialRead.resize(SSH_MAX_PACKET_SIZE * 10);
      }catch(...){
         throw(InetException("SshTransport: Data error."));
      }
   
      setTimeoutMin(5, 0);

      initializer_list<uint8_t> ktypes = { INITIAL_IV_C_TO_S, INITIAL_IV_S_TO_C,    ENCR_KEY_C_TO_S, 
                                           ENCR_KEY_S_TO_C,   INTEGRITY_KEY_C_TO_S, INTEGRITY_KEY_S_TO_C };
      size_t idx = 0;
      for( auto k : ktypes){
         get<KEYTYPE>(keys[idx]) = k;
         idx++;
      }
   
      get<BN_KEYF>(dhReplyPacket)     = BN_new();
      get<BN_EXPONENT>(dhReplyPacket) = BN_new();
      get<BN_MODULUS>(dhReplyPacket)  = BN_new();
   }
   
   SshTransport::~SshTransport(){
      cerr << "\nSsh Connection terminated." << endl;
   
      BN_free(get<BN_KEYF>(dhReplyPacket));        
      BN_free(get<BN_EXPONENT>(dhReplyPacket));        
      BN_free(get<BN_MODULUS>(dhReplyPacket));        

      close(rndFd);
   }
   
   vector<uint8_t>&  SshTransport::setKexMsg(void)  noexcept(false){
      addHeader(SSH_MSG_KEXINIT, clientKexInit); 
      addRandomBytes(COOKIE_LEN, clientKexInit, clientKexInit.size()); 
  
      initializer_list<const string> al ={crypto.getKexAlgs(),     crypto.getHKeyAlgs(),   crypto.getBlkAlgsCtS(),
                                          crypto.getBlkAlgsStC(),  crypto.getMacAlgsCtS(), crypto.getMacAlgsStC(),
                                          crypto.getComprAlgCtS(), crypto.getComprAlgStC() };

      for(auto elem : al) addVarLengthDataString(elem, clientKexInit);   

      try{
         clientKexInit.insert(clientKexInit.end(), sizeof(uint32_t), 0);  // Language client -> server: not supp.
         clientKexInit.insert(clientKexInit.end(), sizeof(uint32_t), 0);  // Language server -> client: not supp.
         clientKexInit.push_back(0);                                      // First_kex_packet_follows = false
         clientKexInit.insert(clientKexInit.end(), KEX_RESERVED_BYTES_LEN, 0);  // Adding reserved-for-future 4 bytes
      }catch(...){
         throw InetException("setKexMsg: Error setting server id.");
      }

      return clientKexInit;
   }
   
   const string& SshTransport::getServerId(void) const noexcept(true){
      return serverIdString;
   }
   
   const string& SshTransport::getClientId(void) const noexcept(true){
      return clientIdString;
   }
   
   void SshTransport::getStatistics(void) const noexcept(true){
      cerr << "* Received " << packetsRcvCount << " ssh packets." << endl 
           << "* Sent     " << packetsSndCount << " ssh packets." << endl;
   }
  
   void SshTransport::readSsh(void) noexcept(false){
      packetsRcvCount++;
      TRACE("\n* Rcv Sequence: " + to_string(packetsRcvCount));

      buffCopy.clear();     
      size_t availableBytes         = 0,
             deltaBytes             = 0;
      while(availableBytes < sizeof(uint32_t)){
         deltaBytes                 = safeSizeT(readBuffer());
         if(deltaBytes > 0){
            availableBytes         += deltaBytes;
            getBufferCopy(buffCopy, true);
         }
      }
      
      size_t requiredBytes          = charToUint32(buffCopy.data()) + sizeof(uint32_t);
      if(requiredBytes  > SSH_MAX_PACKET_SIZE - sizeof(uint32_t))
            throw InetException("readSsh: incoming packet greater than max ssh packet size.");

      TRACE("\n* Rcv Packet: length: " +  to_string(availableBytes) + 
            " - Required: " + to_string(requiredBytes), &buffCopy );

      while(requiredBytes > availableBytes){
          TRACE("\n ** Read again." );
          deltaBytes                = safeSizeT(readBuffer());
          if(deltaBytes > 0){
             availableBytes         += deltaBytes;
             getBufferCopy(buffCopy, true);
             TRACE("\n* Rcv Packet - remaining bytes: ", &buffCopy );
          }
      }
   }

   bool SshTransport::readSshEnc(int chan) noexcept(false){
      int           incomingEncLen,
                    plainTextLen;
      size_t        reassembledLen  = 0,
                    availableBytes;
      bool          status          = true;

      partialRead.clear();
      reassembledLen += safeSizeT(readBuffer(currentBlockLenD));
      if(reassembledLen == 0){
         status      =  false;
         goto INTERRUPTED_BY_SIGNAL;
      }
      try{
         partialRead.insert(partialRead.end(), buffer.begin(), 
                            buffer.begin() + safePtrdiff(currentBlockLenD));
      }catch(...){
            throw InetException("readSshEnc: a : Data error.");
      }

      while( reassembledLen < currentBlockLenD){
         reassembledLen += safeSizeT(readBuffer(currentBlockLenD - reassembledLen));
         try{
            partialRead.insert(partialRead.end(), buffer.begin(), 
                               buffer.begin() + safePtrdiff(currentBlockLenD));
         }catch(...){
               throw InetException("readSshEnc: b : Data error.");
         }
      }
      if(chan != -1){
         createSendPacket(SSH_MSG_CHANNEL_WINDOW_ADJUST,
                          {new VarDataUint32(safeUint32(chan)),
                           new VarDataUint32(safeUint32(currentBlockLenD))
                          });
         TRACE("* Sent SSH_MSG_CHANNEL_WINDOW_ADJUST.\n"); 
      }

      try{
         fill(incomingEnc.begin(), incomingEnc.end(), 0);
      }catch(...){
            throw InetException("readSshEnc: Buffer init error.");
      }
      crypto.decr(partialRead.data(), safeInt(currentBlockLenD), incomingEnc.data(), &incomingEncLen);

      plainTextLen    = incomingEncLen;
      reassembledLen  = charToUint32(incomingEnc.data()) + sizeof(uint32_t) + 
                        currentHashCLen - currentBlockLenD;
      if(reassembledLen  > SSH_MAX_PACKET_SIZE - sizeof(uint32_t) - crypto.getDhHashSize())
            throw InetException("readSshEnc: incoming packet greater than max ssh packet size.");

      TRACE(string("\n* Read Expected Bytes - ") + to_string(reassembledLen + currentBlockLenD) + 
                   " Processed: " + to_string(currentBlockLenD)); 
       
      availableBytes  =  0; 
      while( availableBytes < reassembledLen){
         availableBytes += safeSizeT(readBuffer(reassembledLen - availableBytes));
         try{
            partialRead.insert(partialRead.end(),
                               buffer.begin(), buffer.begin() + readLen);
         }catch(...){
                throw InetException("readSshEnc: c : Data error.");
         }
      }

      TRACE("\n* Rcv Enc Packet - Size: :" + to_string(partialRead.size()) + 
            "\n* Read Expected Bytes - Processed remaining: " + to_string(availableBytes),
            &partialRead);

      if(chan != -1){
         createSendPacket(SSH_MSG_CHANNEL_WINDOW_ADJUST,
                          {new VarDataUint32(safeUint32(chan)),
                           new VarDataUint32(safeUint32(availableBytes))
                          });
         TRACE("* Sent SSH_MSG_CHANNEL_WINDOW_ADJUST.\n"); 
      }
       
      crypto.decr(partialRead.data() + currentBlockLenD,
                  safeInt(partialRead.size() - currentBlockLenD - currentHashCLen),
                  incomingEnc.data() + currentBlockLenD, &incomingEncLen);
           
      plainTextLen    += incomingEncLen;
      
      crypto.decrFin(incomingEnc.data() + plainTextLen, &incomingEncLen);

      plainTextLen    += incomingEncLen;
      packetsRcvCount++;
        
      uint32ToUChars(currentHashS.data(), packetsRcvCount);
      try{
         currentHashS.insert(currentHashS.begin() + sizeof(uint32_t), incomingEnc.begin(), 
                             incomingEnc.begin() + plainTextLen);
      }catch(...){
             throw InetException("readSshEnc: d : Data error.");
      }
   
      crypto.hmacStC(currentHashS.data(), safeInt(sizeof(uint32_t) + safeULong(plainTextLen)),
                     currentHashC.data(), &currentHashCLen);

      TRACE("* Calculating Hash - Rcv Unecrypted and Sequence: " + to_string(packetsRcvCount) + 
            " - Len: " + to_string(sizeof(uint32_t) + safeULong(plainTextLen)), &currentHashS, 
            0, sizeof(uint32_t), currentHashCLen + safeSizeT(plainTextLen));
      TRACE("* Calculated Hash - Len: " + to_string(currentHashCLen), &currentHashC);
 
      if(!equal(currentHashC.cbegin(), currentHashC.cend(),
          partialRead.cbegin() + safePtrdiff(partialRead.size() - currentHashCLen)))
            throw InetException("readSshEnc: Invalid Hash On Incoming Packet");

      TRACE("\n* Rcv Sequence: " + to_string(packetsRcvCount));

      INTERRUPTED_BY_SIGNAL:

      return status;
   }
 
   void SshTransport::writeSshEnc(vector<uint8_t>& msg,  uint8_t allign) noexcept(false){
      size_t        encrTextLen      = 0;
      int           outcomingEncLen  = 0;   
      uint8_t       remind           = (msg.size() + 4) % allign,
                    padding          = allign - remind + 4 ;
      unsigned int  hashLen          = 0; 
   
      msg[sizeof(uint32_t)]       = padding;
      addRandomBytes(padding, msg, msg.size()); 

      uint32ToUChars(msg.data(), safeUint32(msg.size() - sizeof(uint32_t)));

      crypto.encr(msg.data(), safeInt(msg.size()), outcomingEnc.data(), &outcomingEncLen);
      encrTextLen = static_cast<size_t>(outcomingEncLen);

      crypto.encrFin(outcomingEnc.data() + safeSizeT(outcomingEncLen), &outcomingEncLen);

      encrTextLen += static_cast<size_t>(outcomingEncLen);

      packetsSndCount++;
      uint32ToUChars(currentHashS.data(), packetsSndCount);

      insArrayVals(msg, 0,  currentHashS, sizeof(uint32_t));

      TRACE("\n* Snd - Sequence: " + to_string(packetsSndCount) + 
            "\n* Encr. payload length : " + to_string(encrTextLen) + "\n* HMAC Buffer: ",
            &currentHashS, 0, sizeof(uint32_t), msg.size()+sizeof(uint32_t));

      crypto.hmacCtS(currentHashS.data(), safeInt(msg.size() + sizeof(uint32_t)),
                     outcomingEnc.data() + encrTextLen, &hashLen);

      TRACE("* HMAC Len: " + to_string(hashLen) + "\n* Encr + HMAC payload: ", 
                      &outcomingEnc, encrTextLen, encrTextLen + hashLen, 
                      encrTextLen + hashLen);

      writeBuffer(outcomingEnc.data(), encrTextLen + hashLen);
   }
   
   void SshTransport::disconnect(void) noexcept(false){
      if(haveKeys){
         string descr = "Closed by client";
         addHeader(SSH_MSG_DISCONNECT, message);
   
         uint32ToUChars(message, SSH_DISCONNECT_BY_APPLICATION);
         
         addVarLengthDataString(descr, message);
         // Lang
         uint32ToUChars(message, 0);
   
         TRACE("* Sending Disconnect. ");
   
         writeSshEnc(message, AES_BLOCK_LEN_ALLIGN);
      }
   }

   void SshTransport::writeSsh(const uint8_t* msg, size_t size) const noexcept(false){
      packetsSndCount++;
      writeBuffer(msg, size);

      TRACE("* Snd Sequence: " + to_string(packetsSndCount));
   }
   
   void SshTransport::writeSsh(const string& msg) const noexcept(false){
      packetsSndCount++;
      writeBuffer(msg);

      TRACE("* Snd Sequence: " + to_string(packetsSndCount));
   }
   
   void SshTransport::checkSshHeader()       noexcept(false){
      static_cast<void>(readLineTimeout(SSH_MAX_ID_STRING_SIZE));

      serverIdString = currentLine;
      TRACE("* Server Id String: ", reinterpret_cast<const uint8_t*>(serverIdString.c_str()), 
            serverIdString.size());

      if(serverIdString[serverIdString.size() - 2] != 0x0D) 
         throw InetException(string("checkSshHeader: Invalid Server Id String Footer: ") + serverIdString);

      if(!checkHeader(SSH_HEADER_ID))
         throw InetException("checkSshHeader: Unexpected Header");
   }
   
   void SshTransport::addRandomBytes(size_t bytes, vector<uint8_t>& target, 
                                     size_t offset) const noexcept(false){
      try{
         target.insert(target.end(), bytes, 0);
      }catch(...){
         throw InetException("addRandomBytes: Data error");
      }
      if(read(rndFd, target.data() + offset, bytes) < 0)
         throw(InetException("addRandomBytes: Can't read random bytes"));
   }

   void SshTransport::checkServerAlgList(void) noexcept(false){
      sshKexPacket   packet;
      
      try{
         serverKexInit.insert(serverKexInit.end(), buffCopy.begin(),
                              buffCopy.end());  
      }catch(...){
         throw InetException("checkServerAlgList: a : Data error");
      }
  
      packet.packet_length   = charToUint32(buffCopy.data());
      try{
         packet.padding_length  = buffCopy.at(PADDING_LEN_OFFSET);
         packet.kex_packet_type = buffCopy.at(PACKET_TYPE_OFFSET);
      }catch(...){
         throw InetException("checkServerAlgList: a :  Invalid index.");
      }

      if(packet.kex_packet_type != SSH_MSG_KEXINIT){
          trace("Unexpected Packet Type: ", &buffCopy, 0, 0, 
                charToUint32(buffCopy.data()) + sizeof(uint32_t));
          throw InetException(string("checkServerAlgList: Invalid Packet type, expected: ") +
                              to_string(SSH_MSG_KEXINIT) + " - Received: " +
                              to_string(packet.kex_packet_type));
      }

      try{
         packet.server_cookie.insert(packet.server_cookie.end(), 
                                     buffCopy.data() + 6, buffCopy.data() + 16);
      }catch(...){
         throw InetException("checkServerAlgList: b :  Data error.");
      }
   
      TRACE("* Server Alg. List: \n ** Received bytes: " + to_string(buffCopy.size()) +
            "\n ** Packet Length: " + to_string(packet.padding_length) +
            "\n ** Padding: " + to_string(packet.padding_length) + "\n ** Kex Packet Type: " + 
            to_string(packet.kex_packet_type) + "\n ** Server Cookie: ", &(packet.server_cookie));
   
      size_t offset = 22;
      vector<char>buff(buffCopy.size() + 1);
      for(int i=0;i<10;i++){
         offset += getVariableLengthValueCsv(buffCopy, buff,
                   packet.algorithmStrings, i, offset);
      }

      try{ 
         packet.kex_first_pkt_follow  = buffCopy.at(offset + 1);
      }catch(...){
         throw InetException("checkServerAlgList: b :  Invalid index.");
      }

      if(packet.kex_first_pkt_follow != 0){
         TRACE("* Server KEXFOLLOW: " + to_string(buffCopy[offset + 1]));
         throw InetException("checkServerAlgList: Unexpected additional data in kex packet.");
      }
  
      try{ 
         packet.reserved.insert(packet.reserved.end(), buffCopy.data() + offset + 2, 
                                buffCopy.data() + offset + 9);
      }catch(...){
         throw InetException("checkServerAlgList: c :  Data error.");
      }
   
      TRACE("* Reserver Bytes: ", &(packet.reserved));

      crypto.initServerAlgs(packet.algorithmStrings);

      currentBlockLenE             = safeUInt(crypto.getBlockLenE());
      currentBlockLenD             = safeUInt(crypto.getBlockLenD());
      currentHashCLen              = safeUInt(crypto.getDhHashSize());

      try{ 
         currentHashC.resize(currentHashCLen);
      }catch(...){
         throw InetException("checkServerAlgList: d :  Data error.");
      }
   }
   
   void SshTransport::checkServerDhReply(void) noexcept(false){
   
      get<PACKET_LENGTH>(dhReplyPacket)      = charToUint32(buffCopy.data());

      try{
         get<PADDING_LENGTH>(dhReplyPacket)  = buffCopy.at(PADDING_LEN_OFFSET);
         get<KEX_PACKT_TYPE>(dhReplyPacket)  = buffCopy.at(PACKET_TYPE_OFFSET);
      }catch(...){
         throw InetException("checkServerDhReply: a :  Invalid index.");
      }

      try{ 
         get<SERVER_COOKIE>(dhReplyPacket).insert(get<SERVER_COOKIE>(dhReplyPacket).end(), 
                                                  buffCopy.begin() + DATA_OFFSET,
                                                  buffCopy.begin() + DATA_OFFSET + COOKIE_LEN);
      }catch(...){
         throw InetException("checkServerDhReply: a :  Data error.");
      }
   
      TRACE("* Rcv SSH_MSG_NEWKEYS packet - DH Reply: \n ** Received bytes: " + to_string(buffCopy.size()) +
            "\n ** Payload Length: "  + to_string(get<PACKET_LENGTH>(dhReplyPacket) - sizeof(uint32_t)) + 
            "\n ** Padding Length: "  + to_string(get<PADDING_LENGTH>(dhReplyPacket)) +
            "\n ** Kex Packet Type: " + to_string(get<KEX_PACKT_TYPE>(dhReplyPacket)),
            &buffCopy);
   
      genericBuffer.clear();

      try{ 
         genericBuffer.insert(genericBuffer.end(), buffCopy.begin() + safePtrdiff(DATA_OFFSET + sizeof(uint32_t)), 
                              buffCopy.begin() + safePtrdiff(DATA_OFFSET + sizeof(uint32_t) +
                              charToUint32(buffCopy.data() + DATA_OFFSET))); 
      }catch(...){
         throw InetException("checkServerDhReply: b :  Data error.");
      }

      encodeB64(genericBuffer, get<CERTIFICATE_B64>(dhReplyPacket));
   
      TRACE("\n ** Host Blob (Certificate) in B64: \n" + get<CERTIFICATE_B64>(dhReplyPacket) + "\n");
   
      initializer_list<VarDataIn*> outerList    = 
                       {new VarDataBlob<vector<uint8_t>>(get<PUBKEY_BLOB>(dhReplyPacket),    "PK Blob"),
                        new VarDataBNum(get<BN_KEYF>(dhReplyPacket),                         "Key F")}; 
      initializer_list<VarDataIn*> innerList[2] = 
                      {{new VarDataBlob<string>(get<CERTIFICATE_ID>(dhReplyPacket),          "Cert. Id"),
                        new VarDataBNum(get<BN_EXPONENT>(dhReplyPacket),                     "Exponent"),
                        new VarDataBNum(get<BN_MODULUS>(dhReplyPacket),                      "Modulus")}, 
                       {new VarDataBlob<vector<uint8_t>>(get<SIGNATURE_ID>(dhReplyPacket),   "Sign. Id"),
                        new VarDataBlob<vector<uint8_t>>(get<HASH_SIGNATURE>(dhReplyPacket), "Sign. Hash")}};

      size_t offset      = DATA_OFFSET, 
             innerOffset = DATA_OFFSET + sizeof(uint32_t);
      int    mainField   = 0;
  
      for(auto outerElem : outerList){
         offset += outerElem->insertData(buffCopy, offset);
         if(mainField == 1) innerOffset = offset + sizeof(uint32_t);
         for(auto innerElem : innerList[mainField]){
             innerOffset += innerElem->insertData(buffCopy, innerOffset);
             delete innerElem;
         }
         mainField++; 
         delete outerElem;
      }
   
      if(BN_num_bits(get<BN_MODULUS>(dhReplyPacket)) < SSH_RSA_MIN_MODULUS_LENGTH)
         throw InetException("checkServerDhReply: Invalid Modulus size: " + 
                             to_string(BN_num_bits(get<BN_MODULUS>(dhReplyPacket))));
   
      crypto.setDhSharedKey(get<BN_KEYF>(dhReplyPacket));

      vector<uint8_t>  hashBuffer; 
      appendVectBuffer(hashBuffer, clientIdString.c_str(), clientIdString.size()-2, 0, 
                       clientIdString.size() - 3);
      appendVectBuffer(hashBuffer, serverIdString.c_str(), serverIdString.size()-2, 0, 
                       serverIdString.size() - 3);
      appendVectBuffer(hashBuffer, clientKexInit, 5, clientKexInit[4]);
      appendVectBuffer(hashBuffer, serverKexInit, 5, serverKexInit[4]);
      appendVectBuffer(hashBuffer, get<PUBKEY_BLOB>(dhReplyPacket));
   
      // E, F, Shared
      initializer_list<BIGNUM*> list = { crypto.getE(), get<BN_KEYF>(dhReplyPacket), 
                                            crypto.getSharedKey() };

      for(auto elem : list) {
         try{
            genericBuffer.resize(static_cast<size_t>(BN_num_bytes(elem)));
         }catch(...){
            throw InetException("checkServerDhReply: c :  Data error.");
         }
         if( BN_bn2bin(elem, genericBuffer.data()) == 0 ) 
             throw InetException("checkServerDhReply: Wrong Key Element size.");
         if(elem == crypto.getSharedKey())  appendVectBuffer(sharedKey, genericBuffer);
         else                               appendVectBuffer(hashBuffer, genericBuffer);
      }
   
      TRACE("* SK dump : ", &sharedKey);
   
      // Shared
      appendVectBuffer(hashBuffer, genericBuffer);
   
      TRACE("* Hash buffer - added : clientId, serverId, clientKex, \n  serverKex, blob, E, F, SK",
            &hashBuffer);
  
      try{    
         sessionIdHash.resize(SHA_DIGEST_LENGTH);
      }catch(...){
         throw InetException("checkServerDhReply: d :  Data error.");
      }

      crypto.dhHash(hashBuffer, sessionIdHash);
   
      TRACE("* Hash buffer: added SK (Session Id).\n* Session Id dump : ", &sessionIdHash);
      try{ 
         currentSessionHash.insert(currentSessionHash.end(), sessionIdHash.begin(), sessionIdHash.end());
      }catch(...){
         throw InetException("checkServerDhReply: e :  Data error.");
      }
   
      if(sessionIdHash.size() != currentHashCLen)
         throw InetException("checkServerDhReply: Invalid Hash Size.");
  
      crypto.signDH(sessionIdHash,  get<HASH_SIGNATURE>(dhReplyPacket), 
                    get<BN_MODULUS>(dhReplyPacket), get<BN_EXPONENT>(dhReplyPacket));

      checkServerSignature();
   
      if(get<PACKET_LENGTH>(dhReplyPacket) < buffCopy.size()){
         uint32_t next = charToUint32(buffCopy.data() + get<PACKET_LENGTH>(dhReplyPacket) +
                                      sizeof(uint32_t));
   
         TRACE("* Next Len: " + to_string(next));
       
         try{ 
            if(buffCopy.at(get<PACKET_LENGTH>(dhReplyPacket) + 2*sizeof(uint32_t) + sizeof(uint8_t)) 
               != SSH_MSG_NEWKEYS ) {
                  trace("Unexpected Packet Type: ", &buffCopy, 0, 0, 
                        charToUint32(buffCopy.data()) + sizeof(uint32_t));
                  throw InetException(string("checkServerDhReply: Invalid Packet type, expected: ") +
                                      to_string(SSH_MSG_NEWKEYS) + " - Received: " +
                                      to_string(buffCopy[get<PACKET_LENGTH>(dhReplyPacket) + 
                                      sizeof(uint32_t) + sizeof(uint8_t)]));
            }
         }catch(...){
            throw InetException("checkServerDhReply: b :  Invalid index.");
         }
      } else {
         throw InetException("checkServerDhReply: SSH_MSG_NEWKEYS packet not received.");
      }

      packetsRcvCount++;
      haveKeys = true;
   }
   
   void SshTransport::checkServerSignature(void) noexcept(false){
      size_t   idx        = 0;
      Id       line;
      bool     notPresent = true;
      int      fd         = open(knownHosts.c_str(), O_RDWR | O_CREAT, S_IRWXU);
      if(fd == -1)
         throw InetException(string("checkServerSignature: Error opening in the file: ") + knownHosts);
   
      while(notPresent){
         ssize_t size = read(fd, message.data(), SSH_MAX_PACKET_SIZE);
         if(size <= 0) break;
         if(size <  0) throw InetException("checkServerSignature: Error reading knownhost file.");
         try{
            for(size_t i=0; i<static_cast<size_t>(size) && notPresent; i++){
               switch(message[i]){
                  case ' ':
                     idx++;
                  break;
                  case '\n':
                     if(get<CERTIFICATE_B64>(dhReplyPacket).compare(get<2>(line)) == 0){
                        if(hostname.compare(get<0>(line)) == 0 && 
                           get<CERTIFICATE_ID>(dhReplyPacket).compare(get<1>(line)) == 0)
                               notPresent =  false;
                     }
                     get<0>(line).clear();
                     get<1>(line).clear();
                     get<2>(line).clear();
                     idx = 0;
                  break;
                  default:
                     switch(idx){
                        case 0:
                           get<0>(line).push_back(static_cast<char>(message[i]));
                        break;
                        case 1:
                           get<1>(line).push_back(static_cast<char>(message[i]));
                        break;
                        case 2:
                           get<2>(line).push_back(static_cast<char>(message[i]));
                     }
               }
            }
         }catch(...){
            throw InetException("checkServerSignature: Data error.");
         }
      }
   
      string confirm;
      if(notPresent){
         vector<uint8_t> srvIdSign;
         crypto.serverKeyHash(get<CERTIFICATE_B64>(dhReplyPacket), srvIdSign);
         cerr << "The authenticity of host '" << hostname << "' can't be established." << endl
              << "The " << crypto.getDhDescr() << " key fingerprint (SHA256) is:" << endl 
              << srvIdSign.data()  <<  "." << endl
              << "Are you sure you want to continue connecting (yes/no)? " << endl;
   
         getline (cin, confirm);
         while(confirm.compare("yes") != 0  && confirm.compare("no") != 0){
            cerr << "Please type 'yes' or 'no': " << endl;
            getline (cin, confirm);
         }
   
         if(confirm.compare("yes") == 0){
            if(lseek(fd, 0, SEEK_END) == -1)
               throw InetException(string("checkServerSignature: Error positioning in the file: ") +
                                          knownHosts);
            string newEntry;
            try{
               newEntry.append(hostname).append(" ").append(get<CERTIFICATE_ID>(dhReplyPacket));
               newEntry.append(" ").append(get<CERTIFICATE_B64>(dhReplyPacket)).append("\n");;
            }catch(...){
               throw InetException("checkServerSignature: String error.");
            }
            
            if(write(fd, newEntry.c_str(), newEntry.size()) < 0)
               throw InetException("checkServerSignature: Error writing knownhost file.");
   
            TRACE("* Added entry to the file:"  + knownHosts + "\n" + newEntry);

            cerr << "Warning: Permanently added '" + hostname + 
                    "' (" + get<1>(line) + ") to the list of known hosts." 
                 << endl;
         }else{
            throw InetException("checkServerSignature: Host key verification failed.");
         }
      }
      close(fd);
   }
   
   void SshTransport::createKeys(size_t keyLen) noexcept(false){
      // RFC 4253
   
      for(auto i = keys.begin(); i != keys.end(); ++i){
         get<KEYTEXT>(*i).clear();
         try{ 
            get<KEYTEXT>(*i).insert(get<KEYTEXT>(*i).end(), sharedKey.begin(), sharedKey.end());
            get<KEYTEXT>(*i).insert(get<KEYTEXT>(*i).end(), currentSessionHash.begin(), currentSessionHash.end());
            get<KEYTEXT>(*i).push_back(get<KEYTYPE>(*i));
            get<KEYTEXT>(*i).insert(get<KEYTEXT>(*i).end(), sessionIdHash.begin(), sessionIdHash.end());
         }catch(...){
            throw InetException("createKeys: a : Data error.");
         }
   
         size_t currentKeyLen  = currentHashCLen;
         size_t currentHashLen = EVP_MAX_MD_SIZE;
         try{
            get<KEYHASH>(*i).resize(currentKeyLen);
         }catch(...){
            throw InetException("createKeys: b : Data error.");
         }
         crypto.dhHash(get<KEYTEXT>(*i), get<KEYHASH>(*i));
   
         while(get<KEYHASH>(*i).size() < keyLen ){
            currentKeyLen  += currentHashCLen;
            currentHashLen += currentHashCLen;
            try{
               get<KEYTEXT>(*i).resize(currentHashLen);
               get<KEYTEXT>(*i).insert((get<KEYTEXT>(*i).end() - currentHashCLen), 
                                       (get<KEYHASH>(*i).end() - currentHashCLen),
                                       get<KEYHASH>(*i).end());
               get<KEYHASH>(*i).resize(currentKeyLen);
            }catch(...){
               throw InetException("createKeys: c : Data error.");
            }

            crypto.dhHash(get<KEYTEXT>(*i), get<KEYHASH>(*i).data() + (currentKeyLen - currentHashCLen));
         }
         get<KEYHASH>(*i).erase(get<KEYHASH>(*i).end() - 
                                safePtrdiff(get<KEYHASH>(*i).size() - keyLen), 
                                get<KEYHASH>(*i).end());
   
         TRACE("* Hash - " +  string(1, static_cast<char>(get<KEYTYPE>(*i))) + 
               ":", &get<KEYTEXT>(*i));
         TRACE("* Key  - " + string(1, static_cast<char>(get<KEYTYPE>(*i))) + 
               ":", &get<KEYHASH>(*i));
      }
   
      crypto.initBlkEnc(get<KEYHASH>(keys[ENCR_KEY_C_TO_S_IDX]), get<KEYHASH>(keys[INITIAL_IV_C_TO_S_IDX]));
      crypto.initBlkDec(get<KEYHASH>(keys[ENCR_KEY_S_TO_C_IDX]), get<KEYHASH>(keys[INITIAL_IV_S_TO_C_IDX]));

      crypto.initMacCtS(&(get<KEYHASH>(keys[INTEGRITY_KEY_C_TO_S_IDX])));
      crypto.initMacStC(&(get<KEYHASH>(keys[INTEGRITY_KEY_S_TO_C_IDX])));
   }
   
   void SshTransport::addHeader(uint8_t packetType, vector<uint8_t>& buff) const noexcept(false){
         buff.clear();
         try{
            buff.insert(buff.end(), sizeof(uint32_t), 0);  // 4 bytes reserved for packet length
            buff.push_back(0);                             // 1 byte reserved for padding length
            buff.push_back(packetType);                    // 1 byte message type
         }catch(...){
            throw InetException("addHeader : Data error.");
         }
   }

   void  SshTransport::sendWithHeader(vector<uint8_t>& buff, uint8_t allign) const noexcept(false){
         const uint8_t* vectHandler   = buff.data();
         uint8_t        remind        = (buff.size() + 4) % allign,
                        padding       = allign - remind + 4 ;
   
         buff[PADDING_LEN_OFFSET] = padding;
         try{
            buff.insert(buff.end(), padding, 0);  // Added padding
         }catch(...){
            throw InetException("sendWithHeader : Data error.");
         }
   
         size_t         bufferLength  = buff.size() ;
         uint32ToUChars(buff.data(), safeUint32(buff.size() - sizeof(uint32_t)));
               
         writeSsh(vectHandler, bufferLength);
   
         TRACE("* Send With Header - Msg type: " + to_string(buff[PACKET_TYPE_OFFSET]) +
               "\n ** Calculated padding: " + to_string(padding) + 
               "\n ** Length: " + to_string(bufferLength), &buff);
   }
  
   void SshTransport::createSendPacket(const uint8_t packetType, 
                                       initializer_list<VarData*>&& list) noexcept(false){
      addHeader(packetType, message); 
      for(auto elem : list) {
         elem->appendData(message);
         delete elem;
      }
      writeSshEnc(message, AES_BLOCK_LEN_ALLIGN);
      TRACE("* Buffer Capacity: " + to_string(message.capacity()));
   }

   void Fsm::setInitStat(unsigned int status) noexcept(true){
      currStat = status;
   }

   void Fsm::setTree(StatusTree* tree) noexcept(true){ 
      statuses = tree;
   }

   void Fsm::checkStatus(unsigned int newStat) noexcept(false){
      auto i  = statuses->find(newStat);
      if( i  == statuses->end())
         throw InetException("checkStatus: Fsm Error: invalid status " + to_string(newStat) + ".");

      auto ii = i->second.find(currStat);
      if( ii == i->second.cend())
         throw InetException("checkStatus: Packet sequence error: unexpected packet sequence: " +
                             to_string(currStat) + " --> " + to_string(newStat));

      currStat = newStat;
   }
   
   SshConnection::SshConnection(string& usr, string& host, string& port,
                                 bool noTerm, std::string& identity,uint32_t chan) : 
            SshTransport(host, port), sWinch(0), noTTY(noTerm), nonCanonical(false), user(usr), 
            idFilePref(identity), channelNumber(chan), remoteChannelNumber(0), initialWindowsSize(0), 
            maxPacketSize(0)                    {

      if(tcgetattr(STDIN_FILENO, &termOld) == -1 )
         throw InetException("SshConnection: Error getting terminal attributes.");

      try{
         extData.reserve(SSH_MAX_PACKET_SIZE);
         keybInputData.reserve(SSH_MAX_PACKET_SIZE);
      }catch(...){
         throw InetException("SshConnection: Data error.");
      }
      static_cast<void>(sigfillset(&sigsetBlockAll));
      if(sigprocmask(0, nullptr, &sigsetBackup) != 0)
         throw InetException("SshConnection: Error getting the signal mask.");
   }

   SshConnection::~SshConnection(){
      if(nonCanonical){
         if(tcsetattr(STDIN_FILENO, TCSANOW, &termOld) == -1)
            throw InetException("~SshConnection: Error resetting terminal in canonical mode.");
      }
      ERR_clear_error();  
   }
   
   void  SshConnection::createAuthSign(vector<uint8_t>& msg, initializer_list<VarData*>&& list) noexcept(false){
      genericBuffer.clear();
      for(auto elem : list) {
         elem->appendData(genericBuffer);
         delete elem;
      }
      crypto.signMessage(privKey, genericBuffer, msg);
   }
   
   void  SshConnection::createSendShellData() noexcept(false){
      addHeader(SSH_MSG_CHANNEL_DATA, message); 
      uint32ToUChars(message, channelNumber);
      addVarLengthDataString(keybInputData, message);
      writeSshEnc(message, AES_BLOCK_LEN_ALLIGN);
   }

   void SshConnection::getUserKeyFiles(void) noexcept(false){
      try{
         pubKey.append(getenv("HOME")).append("/").append(SSH_CONF_DIRECTORY);
         privKey = pubKey;
         knownHosts.append(pubKey).append("/").append(SSH_KNOWN_HOST_FILE);
      }catch(...){
         throw InetException("getUserKeyFiles: a : String error.");
      }
   
      if(mkdir(pubKey.c_str(), 0700) != 0 && errno != EEXIST)
         throw InetException(string("getUserKeyFiles: Error Checking Conf Dir: ") + strerror(errno));
      errno = 0;
   
      try{
         pubKey.append("/").append(idFilePref.empty() ? crypto.getKeyFilePrefix() : idFilePref).append(".pub");
         privKey.append("/").append(idFilePref.empty() ? crypto.getKeyFilePrefix() : idFilePref);
      }catch(...){
         throw InetException("getUserKeyFiles: b : String error.");
      }
   }

   void SshConnection::getUserPubK(void) noexcept(false){
      try{
         loadFileMem(pubKey, genericBuffer, true);
      }catch(StringUtilsException& e){
         TRACE("* Public Key - " + e.what() + "\n  Using Null Key.");
         genericBuffer.clear();
         try{
            string nullKey = crypto.getDhId() + " " + crypto.getNullKey() + " " + user;
            genericBuffer.insert(genericBuffer.end(), nullKey.begin(), nullKey.end());
            genericBuffer.push_back(0);
         }catch(...){
            throw InetException("getUserPubK: Data error.");
         }
      }
      
      char*       flag              = strtok(reinterpret_cast<char*>(genericBuffer.data()), " ");
      get<PUBKEYTYPE>(clientPubKey) = flag;
      flag = strtok(nullptr, " ");
      decodeB64(string(flag), get<PUBKEYBLOB>(clientPubKey));
      flag = strtok(nullptr, " ");
      get<PUBKEYUSR>(clientPubKey)  = flag;
   
      TRACE("* Client PubK Type: " + get<PUBKEYTYPE>(clientPubKey) + "\n ** Client PubK Usr: " + 
            get<PUBKEYUSR>(clientPubKey) + "\n ** Client PubK Blob: ", &get<PUBKEYBLOB>(clientPubKey));
   }

   void SshConnection::connectionLoop(void) noexcept(false){
      bool              again             = true,
                        pubKeyAuth        = false,
                        password          = false,
                        keybInter         = false;
      uint32_t          errCode,
                        confirmedChannel;
      string            tmp;
      size_t            offset            = 0;
      StatusTree        tree              = 
                        { 
                          {SSH_MSG_SERVICE_ACCEPT,            {SSH_CONN_START}},  
                          {SSH_MSG_USERAUTH_FAILURE,          {SSH_MSG_SERVICE_ACCEPT,
                                                               SSH_MSG_USERAUTH_FAILURE,
                                                               SSH_MSG_USERAUTH_INFO_REQUEST}},  
                          {SSH_MSG_USERAUTH_INFO_REQUEST,     {SSH_MSG_SERVICE_ACCEPT,
                                                               SSH_MSG_USERAUTH_INFO_REQUEST,
                                                               SSH_MSG_USERAUTH_FAILURE}},
                          {SSH_MSG_USERAUTH_SUCCESS,          {SSH_MSG_USERAUTH_INFO_REQUEST,
                                                               SSH_MSG_USERAUTH_FAILURE}},
                          {SSH_MSG_CHANNEL_OPEN_CONFIRMATION, {SSH_MSG_USERAUTH_SUCCESS}},
                          {SSH_MSG_CHANNEL_WINDOW_ADJUST,     {SSH_MSG_CHANNEL_OPEN_CONFIRMATION}}
                        };

      fsm.setInitStat(SSH_CONN_START);
      fsm.setTree(&tree);
      createSendPacket(SSH_MSG_SERVICE_REQUEST, {new VarDataCharArr(SSH_USERAUTH_STRING)});

      while(again){
         static_cast<void>(readSshEnc());
         switch(incomingEnc[PACKET_TYPE_OFFSET]){
            case SSH_MSG_IGNORE:
               TRACE( "* Received SSH_MSG_IGNORE: nothing to do.");
            break;
            case SSH_MSG_USERAUTH_INFO_REQUEST:
               TRACE("* Received SSH_MSG_USERAUTH_INFO_REQUEST.");
               fsm.checkStatus(SSH_MSG_USERAUTH_INFO_REQUEST);

               if(keybInter){
                  offset  = DATA_OFFSET;
                  tmp.clear();
                  offset  += getVariableLengthRawValue(incomingEnc, offset, tmp);
                  tmp.clear();
                  offset  += getVariableLengthRawValue(incomingEnc, offset, tmp);
                  tmp.clear();
                  offset  += getVariableLengthRawValue(incomingEnc, offset, tmp);
                  uint32_t numPrompts = charToUint32(incomingEnc.data() + offset);
   
                  if(numPrompts == 0 ){
                     createSendPacket(SSH_MSG_USERAUTH_INFO_RESPONSE,
                            {new VarDataUint32(0)
                            });
                  }else{
                     genericBuffer.clear();
                     try{
                        getPassword(genericBuffer, &termOld, &termNew);
                     }catch(StringUtilsException& e){
                        nonCanonical = true;
                        throw InetException(string("connectionLoop: " + e.what()));
                     }
                     createSendPacket(SSH_MSG_USERAUTH_INFO_RESPONSE,
                            {new VarDataUint32(numPrompts),
                             new VarDataString<vector<uint8_t> >
                                 (genericBuffer)
                            });
                     secureZeroing(genericBuffer.data(), genericBuffer.size());
                  }
               }else if(!pubKeyAuth){
                  vector<uint8_t> sign; 
                  createAuthSign(sign,
                     {new VarDataString<vector<uint8_t>>
                          (sessionIdHash),
                      new VarDataChar(SSH_MSG_USERAUTH_REQUEST),
                      new VarDataString<string>(user),
                      new VarDataCharArr(SSH_CONNECT_STRING),
                      new VarDataCharArr(SSH_PUBKEY_AUTH_REQ),
                      new VarDataChar(1),
                      new VarDataString<string>
                         (get<PUBKEYTYPE>(clientPubKey)),
                      new VarDataString<vector<uint8_t> > 
                         (get<PUBKEYBLOB>(clientPubKey))
                      });
      
                   createSendPacket(SSH_MSG_USERAUTH_REQUEST, 
                      {new VarDataString<string>(user),
                       new VarDataCharArr(SSH_CONNECT_STRING),
                       new VarDataCharArr(SSH_PUBKEY_AUTH_REQ),
                       new VarDataChar(1),
                       new VarDataString<string>
                              (get<PUBKEYTYPE>(clientPubKey)),
                       new VarDataString<vector<uint8_t> > 
                           (get<PUBKEYBLOB>(clientPubKey)),
                       new VarDataRecursive(
                          { new VarDataString<string>
                               (get<PUBKEYTYPE>(clientPubKey)),
                            new VarDataString<vector<uint8_t> >
                                (sign)
                          })
                       });
   
                     pubKeyAuth = true;
               }
            break;
            case SSH_MSG_SERVICE_ACCEPT:
                TRACE("* Received SSH_MSG_SERVICE_ACCEPT: Trying pubkey.");
                fsm.checkStatus(SSH_MSG_SERVICE_ACCEPT);
                createSendPacket(SSH_MSG_USERAUTH_REQUEST, 
                   {new VarDataString<string>(user),
                    new VarDataCharArr(SSH_CONNECT_STRING),
                    new VarDataCharArr(SSH_PUBKEY_AUTH_REQ),
                    new VarDataChar(0),
                    new VarDataString<string>(
                        get<PUBKEYTYPE>(clientPubKey)),
                    new VarDataString<vector<uint8_t>>(
                        get<PUBKEYBLOB>(clientPubKey))
                    });
            break;
            case SSH_MSG_USERAUTH_SUCCESS:
                TRACE( "* Received SSH_MSG_USERAUTH_SUCCESS: auth ok.");
                fsm.checkStatus(SSH_MSG_USERAUTH_SUCCESS);
                createSendPacket(SSH_MSG_CHANNEL_OPEN,
                   { new VarDataCharArr(SSH_SESSION_SPEC),
                     new VarDataUint32(channelNumber),
                     new VarDataUint32(SSH_MAX_PACKET_SIZE * 4),
                     new VarDataUint32(SSH_MAX_PACKET_SIZE / 2)
                   });
            break;
            case SSH_MSG_USERAUTH_FAILURE:
               fsm.checkStatus(SSH_MSG_USERAUTH_FAILURE);
               if(!keybInter){
                  TRACE("  ** SSH_MSG_USERAUTH_FAILURE: Trying keyb-inter.");
   
                  createSendPacket(SSH_MSG_USERAUTH_REQUEST,
                         {new VarDataString<string>(user),
                          new VarDataCharArr(SSH_CONNECT_STRING),
                          new VarDataCharArr(SSH_KEYB_INTER_SPEC),
                          new VarDataCharArr(""),
                          new VarDataCharArr("")
                         });
                  keybInter = true;
               }else if(!password){
                  TRACE("  ** SSH_MSG_USERAUTH_FAILURE: Trying password.");
                  genericBuffer.clear();
                  try{
                     getPassword(genericBuffer, &termOld, &termNew);
                  }catch(StringUtilsException& e){
                     nonCanonical = true;
                     throw InetException(string("connectionLoop: " + e.what()));
                  }
                  createSendPacket(SSH_MSG_USERAUTH_REQUEST, 
                         {new VarDataString<string>(user),
                          new VarDataCharArr(SSH_CONNECT_STRING),
                          new VarDataCharArr(SSH_PASSWD_SPEC),
                          new VarDataChar(0), 
                          new VarDataString<vector<uint8_t> >
                              (genericBuffer)
                         });
                  secureZeroing(genericBuffer.data(), genericBuffer.size());
                  password = true;
               }else{
                  throw InetException("connectionLoop: Error: SSH_MSG_USERAUTH_FAILURE.");
               }
            break;
            case SSH_MSG_USERAUTH_BANNER:
               // Any time: info banner.
               TRACE("* Received SSH_MSG_USERAUTH_BANNER.");
            break;
            case SSH_MSG_UNIMPLEMENTED:
                throw InetException("connectionLoop: Error: SSH_MSG_UNIMPLEMENTED.");
            case SSH_MSG_DISCONNECT:
                offset  = DATA_OFFSET;
                errCode = charToUint32(incomingEnc.data() + offset);
                offset += sizeof(uint32_t);
                getVariableLengthRawValue(incomingEnc, offset, tmp);
                trace("SSH_MSG_DISCONNECT packet: ", &incomingEnc, 0, 0, 
                      charToUint32(incomingEnc.data()) + sizeof(uint32_t));
                throw InetException(string("connectionLoop: Received SSH_MSG_DISCONNECT: ") +
                                    to_string(errCode) + " Description: " + tmp);
            case SSH_MSG_GLOBAL_REQUEST:
                // Any time : WindowsSize, max_packet_size.
                TRACE( "* Received SSH_MSG_GLOBAL_REQUEST.");
                createSendPacket(SSH_MSG_REQUEST_FAILURE, {} );
                createSendPacket(SSH_MSG_CHANNEL_OPEN,
                      { new VarDataCharArr(SSH_SESSION_SPEC),
                        new VarDataUint32(channelNumber),
                        new VarDataUint32(SSH_MAX_PACKET_SIZE * 4),
                        new VarDataUint32(SSH_MAX_PACKET_SIZE / 2)
                      });
            break;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
               fsm.checkStatus(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
                offset  = DATA_OFFSET;
                confirmedChannel = charToUint32(incomingEnc.data() + offset);
                offset += sizeof(uint32_t);
                remoteChannelNumber = charToUint32(incomingEnc.data() + offset);
                offset += sizeof(uint32_t);
                initialWindowsSize = charToUint32(incomingEnc.data() + offset);
                offset += sizeof(uint32_t);
                maxPacketSize = charToUint32(incomingEnc.data() + offset);
                TRACE("* Received SSH_MSG_CHANNEL_OPEN_CONFIRMATION:\n ** Local Channel Number: " +
                      to_string(confirmedChannel) + "\n ** Remote Channel Number: " +
                      to_string(remoteChannelNumber) + "\n ** Initial Window Size: " +
                      to_string(initialWindowsSize) + "\n ** Max Packet Size: " +
                      to_string(maxPacketSize) + "\n");
                if(channelNumber != confirmedChannel)
                   throw InetException("connectionLoop: Local channel number mismatch: " + 
                                       to_string(channelNumber));
                if(!noTTY){
                    if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &windowAttr) == -1)
                       throw InetException("connectionLoop: Ioctl Error: reading window size.");
                    genericBuffer.clear();
                    initializer_list<uint32_t> termAttr = {
                           termOld.c_cc[VINTR], termOld.c_cc[VQUIT],    termOld.c_cc[VERASE],
                           termOld.c_cc[VKILL], termOld.c_cc[VEOF],     termOld.c_cc[VEOL],
                           termOld.c_cc[VEOL2], termOld.c_cc[VSTART],   termOld.c_cc[VSTOP],
                           termOld.c_cc[VSUSP], termOld.c_cc[VREPRINT], termOld.c_cc[VWERASE],
                           termOld.c_cc[VLNEXT] };
                    
                    uint8_t idx = 0;
                    for(auto elem : termAttr){
                       idx += idx != 10 ? 1 : 2;
                       try{
                          genericBuffer.push_back(idx);
                       }catch(...){
                          throw InetException("connectionLoop: a : Data error.");
                       }
                       try{
                          uint32ToUChars(genericBuffer, elem);
                       }catch(...){
                          throw InetException("connectionLoop: b : Data error.");
                       }
                    }
                    try{
                       genericBuffer.push_back(0);
                    }catch(...){
                       throw InetException("connectionLoop: c : Data error.");
                    }

                    const char* term = getenv("TERM");
                    if(term == nullptr) term = SSH_DEFAULT_TERM;
                    
                    TRACE("* Sent pty request - Rows: " + to_string(windowAttr.ws_row) + 
                          " - Cols: " + to_string(windowAttr.ws_col) + "\n");
                    createSendPacket(SSH_MSG_CHANNEL_REQUEST,
                          { new VarDataUint32(remoteChannelNumber),
                            new VarDataCharArr(SSH_PTY_REQ),
                            new VarDataChar(1),
                            new VarDataCharArr(term), 
                            new VarDataUint32(windowAttr.ws_col), 
                            new VarDataUint32(windowAttr.ws_row), 
                            new VarDataUint32(0), 
                            new VarDataUint32(0), 
                            new VarDataString<vector<uint8_t> >
                                (genericBuffer)
                          });
                }
                TRACE("* Sent shell request.");
                createSendPacket(SSH_MSG_CHANNEL_REQUEST,
                      { new VarDataUint32(remoteChannelNumber),
                        new VarDataCharArr(SSH_SHELL_REQ),
                        new VarDataChar(1) 
                      });

                again = false;
            break;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                offset  = DATA_OFFSET;
                confirmedChannel = charToUint32(incomingEnc.data() + offset);
                offset += sizeof(uint32_t);
                bytesToAdd = charToUint32(incomingEnc.data() + offset);
                TRACE("* Received SSH_MSG_CHANNEL_WINDOW_ADJUST:\n ** Local Channel: " + 
                      to_string(confirmedChannel) + "\n ** Bytes to Add : " +
                      to_string(bytesToAdd) + "\n");
               initialWindowsSize += bytesToAdd;
            break;
            default:
                trace("Dump: ", &incomingEnc, 0, 0, 
                      charToUint32(incomingEnc.data()) + sizeof(uint32_t));
                throw InetException(string("connectionLoop: Shell Connection - Unespected Packet Type: ") + 
                                    to_string(incomingEnc[PACKET_TYPE_OFFSET]));
         }
      }
   }

   void SshConnection::shellLoop(void) noexcept(false){
      fd_set            readfds;
      bool              again               = true;
      uint8_t           inputKey;

      while(again){

         FD_ZERO(&readfds);
         FD_SET(*(handler.peerFd), &readfds);
         FD_SET(STDIN_FILENO,      &readfds);
   
         if(select(*(handler.peerFd)+1, &readfds, nullptr, nullptr, nullptr) < 0)
            throw InetException(string("shellLoop: Select error in shell loop: ") + strerror(errno));
   
         if(FD_ISSET(STDIN_FILENO, &readfds)){
            if(read(STDIN_FILENO, &inputKey, 1) < 0)
               throw InetException("shellLoop: Error reading stdin.");
     
            try{ 
               keybInputData.push_back(inputKey);
            }catch(...){
               throw InetException("shellLoop: Data error.");
            }
            if( inputKey == '\n' || keybInputData.size() == (maxPacketSize - currentHashCLen)){
               createSendShellData();
               keybInputData.clear();
            }
         }
   
         if(FD_ISSET(*(handler.peerFd), &readfds)){
            if(readSshEnc(safeInt(channelNumber)))
               again = parseShellPacket(); 
         }
      }
   }

   static SshConnection* sigRef;
   
   void SshConnection::adjustWnwSize(void) const noexcept(true){
      sWinch = 1;
   }
  
   void SshConnection::shellLoopPty(void) noexcept(false){
                   sigRef             = this;
      fd_set       readfds;
      bool         again              = true;

      termNew                         = termOld;
      termNew.c_lflag                 &= static_cast<unsigned long>(~(ICANON | ISIG | ECHO));
      termNew.c_cc[VMIN]              = 1;
      termNew.c_cc[VTIME]             = 0;

      if(tcsetattr(STDIN_FILENO, TCSANOW, &termNew) == -1)
         throw InetException("shellLoopPty: Error setting terminal in non-canonical mode.");

      nonCanonical = true;

      #ifdef __clang__
      #pragma clang diagnostic push
      #pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
      #endif

      sigemptyset(&sigActionWndw.sa_mask);
      sigActionWndw.sa_flags          = 0;
      sigActionWndw.sa_handler = [](int){ sigRef->adjustWnwSize();};
      if(sigaction(SIGWINCH, &sigActionWndw, nullptr) != 0)
         throw InetException("shellLoopPty: Error reading stdin.");

      #ifdef __clang__
      #pragma clang diagnostic pop 
      #endif

      keybInputData.clear();
      try{
         keybInputData.push_back(0);
      }catch(...){
         throw InetException("shellLoopPty: Data error.");
      }

      while(again){

         FD_ZERO(&readfds);
         FD_SET(*(handler.peerFd), &readfds);
         FD_SET(STDIN_FILENO,      &readfds);
 
         if(select(*(handler.peerFd)+1, &readfds, nullptr, nullptr, nullptr) < 0 && errno != EINTR)
               throw InetException(string("shellLoopPty: Select error in shell loop: ") + strerror(errno));

         if( sWinch == 1){ 
            if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &windowAttr) == -1)
               throw InetException("shellLoopPty: Ioctl Error: reading window size.");
               
            createSendPacket(SSH_MSG_CHANNEL_REQUEST,
                  { new VarDataUint32(remoteChannelNumber),
                    new VarDataCharArr(SSH_WNDW_RESIZE),
                    new VarDataChar(0),
                    new VarDataUint32(windowAttr.ws_col), 
                    new VarDataUint32(windowAttr.ws_row), 
                    new VarDataUint32(0), 
                    new VarDataUint32(0) 
                  });
   
            static_cast<void>(tcflush(STDIN_FILENO, TCIFLUSH));

            sWinch = 0;
            continue;
         }

         if(FD_ISSET(STDIN_FILENO, &readfds) && sWinch == 0){
            ssize_t rd = read(STDIN_FILENO, keybInputData.data(), 1);
            if(rd < 0 && errno != EINTR)
               throw InetException("shellLoopPty: Error reading stdin.");
            if(rd == 1){
               createSendShellData();
            }
         }
   
         if(FD_ISSET(*(handler.peerFd), &readfds) && sWinch == 0){
            static_cast<void>(readSshEnc(safeInt(channelNumber)));
            again = parseShellPacket(); 
         }

      }
   }

   bool SshConnection::parseShellPacket(void) noexcept(false){
     size_t      offset             = 0;
     bool        again              = true;
     uint32_t    confirmedChannel,
                 dataTypeCode;
     bool        firstWnwReceided   = true;
     StatusTree  tree               = 
                 { 
                   {SSH_MSG_CHANNEL_SUCCESS,           {SSH_MSG_CHANNEL_WINDOW_ADJUST,
                                                        SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                                                        SSH_MSG_CHANNEL_SUCCESS}},
                   {SSH_MSG_CHANNEL_OPEN_CONFIRMATION, {SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                                                        SSH_MSG_CHANNEL_SUCCESS}},
                   {SSH_MSG_CHANNEL_WINDOW_ADJUST,     {SSH_MSG_CHANNEL_SUCCESS,
                                                        SSH_MSG_CHANNEL_OPEN_CONFIRMATION}}
                 };
     fsm.setTree(&tree);

     switch(incomingEnc[PACKET_TYPE_OFFSET]){
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
           offset  = DATA_OFFSET;
           confirmedChannel = charToUint32( incomingEnc.data() + offset);
           offset += sizeof(uint32_t);
           dataTypeCode = charToUint32( incomingEnc.data() + offset);
           if( dataTypeCode != CHANNEL_EXTDATA_STDERR)
              throw InetException("parseShellPacket: Invalid ExtData Type.");
           extData.clear();
           offset += sizeof(uint32_t);
           offset += getVariableLengthRawValue(incomingEnc, offset, extData);
           try{
              extData.push_back(0);
           }catch(...){
              throw InetException("parseShellPacket: a : Data error.");
           }
           TRACE(string("* Received SSH_MSG_CHANNEL_EXTENDED_DATA:\n") +
                        " ** Local Channel: " + to_string(confirmedChannel) +
                        "\n ** Data Type : " + to_string(dataTypeCode) +
                        "\n ** Stderr:\n");
           cerr << extData.data();
        break;
        case SSH_MSG_CHANNEL_DATA:
           offset  = DATA_OFFSET;
           confirmedChannel = charToUint32( incomingEnc.data() + offset);
           extData.clear();
           offset += sizeof(uint32_t);
           offset += getVariableLengthRawValue(incomingEnc, offset, extData);
           try{
              extData.push_back(0);
           }catch(...){
              throw InetException("parseShellPacket: b : Data error.");
           }
           TRACE(string("* Received SSH_MSG_CHANNEL_DATA:\n") +
                        " ** Local Channel: " + to_string(confirmedChannel) + 
                        "\n ** Stdout:\n");
           cout << extData.data();
           cout.flush(); 
        break;
        case SSH_MSG_CHANNEL_REQUEST:
           TRACE("* Received SSH_MSG_CHANNEL_REQUEST: end loop.");
           again = false;
        break;
        case SSH_MSG_CHANNEL_WINDOW_ADJUST:
           if(firstWnwReceided){
              fsm.checkStatus(SSH_MSG_CHANNEL_WINDOW_ADJUST);
              firstWnwReceided = false;
           }
           offset  = DATA_OFFSET;
           confirmedChannel = charToUint32(incomingEnc.data() + offset);
           offset += sizeof(uint32_t);
           bytesToAdd = charToUint32(incomingEnc.data() + offset);
           TRACE(string("* Received SSH_MSG_CHANNEL_WINDOW_ADJUST:\n") +
                        " ** Local Channel: " + to_string(confirmedChannel) +
                        "\n ** Bytes to Add : " + to_string(bytesToAdd) + "\n");
           initialWindowsSize += bytesToAdd;
        break;
        case SSH_MSG_CHANNEL_SUCCESS:
           TRACE("* Received SSH_MSG_CHANNEL_SUCCESS.");
           fsm.checkStatus(SSH_MSG_CHANNEL_SUCCESS);
        break;
        case SSH_MSG_CHANNEL_EOF:
           TRACE("* Received SSH_MSG_CHANNEL_EOF.");
           createSendPacket(SSH_MSG_CHANNEL_EOF,
               { new VarDataUint32(remoteChannelNumber)
               });
           again = false;
        break;
        case SSH_MSG_CHANNEL_CLOSE:
           TRACE("* Received SSH_MSG_CHANNEL_CLOSE.");
           again = false;
        break;
        case SSH_MSG_IGNORE:
           TRACE( "* Received SSH_MSG_IGNORE: nothing to do.");
        break;
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
           TRACE( "* Received SSH_MSG_CHANNEL_OPEN_CONFIRMATION: shell loop.");
           fsm.checkStatus(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        break;
        case SSH_MSG_DISCONNECT:
           trace("SSH_MSG_DISCONNECT packet: ", &incomingEnc, 0, 0, 
                 charToUint32(incomingEnc.data()) + sizeof(uint32_t));
           throw InetException("parseShellPacket: Received SSH_MSG_DISCONNECT: ");
        case SSH_MSG_CHANNEL_OPEN_FAILURE:
           throw InetException("parseShellPacket: SSH_MSG_CHANNEL_OPEN_FAILURE.");
        case SSH_MSG_CHANNEL_FAILURE:
           TRACE("* Received SSH_MSG_CHANNEL_FAILURE.");
           throw InetException("parseShellPacket: SSH_MSG_CHANNEL_FAILURE.");
        default:
           trace("Dump: ", &incomingEnc, 0, 0, 
                 charToUint32(incomingEnc.data()) + sizeof(uint32_t));
           throw InetException(string("parseShellPacket: Unespected Packet Type: ") +
                                      to_string(incomingEnc[PACKET_TYPE_OFFSET]));
     }

     return again;
   }

   void SshConnection::getShell() noexcept(false){
      writeBuffer(getClientId());
      checkSshHeader();
   
      // Handshake
      sendWithHeader(setKexMsg(), BEGINNING_BLOCK_LEN_ALLIGN);
      readSsh();
      checkServerAlgList();

      getUserKeyFiles();
      
      vector<uint8_t> msg;
      try{
         msg.reserve(10240);
      }catch(...){
         throw InetException("getShell: b : Data error.");
      }
   
      //DH 
      addHeader(SSH_MSG_KEX_DH_GEX_REQUEST_OLD, msg);

      crypto.setDhKeys(genericBuffer, msg);
   
      sendWithHeader(msg, BEGINNING_BLOCK_LEN_ALLIGN);
      readSsh();

      checkServerDhReply();
   
      createKeys(currentHashCLen);
      addHeader(SSH_MSG_NEWKEYS, msg);
      sendWithHeader(msg, BEGINNING_BLOCK_LEN_ALLIGN);
   
      getUserPubK();  
  
      // Connect 
      connectionLoop();
  
      // Shell 
      if(noTTY)
         shellLoop();
      else
         shellLoopPty();
   }

   #if defined  __clang_major__ && !defined __APPLE__ && __clang_major__ >= 4
   #pragma clang diagnostic pop 
   #endif

}
