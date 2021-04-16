// -----------------------------------------------------------------
// Tssh - A ssh test client. 
// Copyright (C) 2016-2021  Gabriele Bonacini
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

#ifndef TSSH_LIB
#define TSSH_LIB

#include <openssl/bn.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <stdlib.h>
#include <signal.h>

#include <initializer_list>
#include <algorithm>
#include <utility>
#include <map>
#include <set>

#include <anyexcept.hpp>
#include <Types.hpp>
#include <StringUtils.hpp>
#include <Inet.hpp>
#include <Crypto.hpp>

enum CONFILEN { COOKIE_LEN                  = 16,    KEX_RESERVED_BYTES_LEN        = 4,
                PADDING_LEN_OFFSET          = 4,     DATA_OFFSET                   = 6,
                PACKET_TYPE_OFFSET          = 5,     SSH_RSA_MIN_MODULUS_LENGTH    = 768,
                SSH_MAX_PACKET_SIZE         = 35000, SSH_MAX_ID_STRING_SIZE        = 255, 
                SSH_STD_KEYS_NUMBER         = 6,     BEGINNING_BLOCK_LEN_ALLIGN    = 8,
                AES_BLOCK_LEN_ALLIGN        = 64,    SERVER_ALG_OFFSET             = 22
};

enum HNDSHKIDX { INITIAL_IV_C_TO_S_IDX      = 0,     INITIAL_IV_S_TO_C_IDX         = 1,
                 ENCR_KEY_C_TO_S_IDX        = 2,     ENCR_KEY_S_TO_C_IDX           = 3,
                 INTEGRITY_KEY_C_TO_S_IDX   = 4,     INTEGRITY_KEY_S_TO_C_IDX      = 5
};
 
enum CONFETC   { CHANNEL_EXTDATA_STDERR     = 1,     SSH_PTY_ECHO  = 53                     };
enum KEYATTCOL { KEYTEXT                    = 0,     KEYTYPE       = 1,      KEYHASH    = 2 };
enum PUBKEYIDX { PUBKEYTYPE                 = 0,     PUBKEYBLOB    = 1,      PUBKEYUSR  = 2 };

//      SSH_MSG_USERAUTH_PK_OK              60
//      SSH_MSG_REQUEST_SUCCESS             81

enum STATUS { SSH_CONN_START                 = 0,    
              SSH_MSG_DISCONNECT             = 1,    SSH_MSG_IGNORE                    = 2,
              SSH_MSG_UNIMPLEMENTED          = 3,    SSH_MSG_DEBUG                     = 4,    
              SSH_MSG_SERVICE_REQUEST        = 5,    SSH_MSG_SERVICE_ACCEPT            = 6,    
              SSH_DISCONNECT_BY_APPLICATION  = 11,   SSH_MSG_KEXINIT                   = 20,
              SSH_MSG_NEWKEYS                = 21,   SSH_MSG_KEX_DH_GEX_REQUEST_OLD    = 30,
              SSH_MSG_USERAUTH_REQUEST       = 50,   SSH_MSG_USERAUTH_FAILURE          = 51,
              SSH_MSG_USERAUTH_SUCCESS       = 52,   SSH_MSG_USERAUTH_BANNER           = 53,
              SSH_MSG_USERAUTH_INFO_REQUEST  = 60,   SSH_MSG_USERAUTH_INFO_RESPONSE    = 61,
              SSH_MSG_GLOBAL_REQUEST         = 80,   SSH_MSG_REQUEST_FAILURE           = 82,
              SSH_MSG_CHANNEL_OPEN           = 90,   SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
              SSH_MSG_CHANNEL_OPEN_FAILURE   = 92,   SSH_MSG_CHANNEL_WINDOW_ADJUST     = 93,
              SSH_MSG_CHANNEL_DATA           = 94,   SSH_MSG_CHANNEL_EXTENDED_DATA     = 95,
              SSH_MSG_CHANNEL_EOF            = 96,   SSH_MSG_CHANNEL_CLOSE             = 97,
              SSH_MSG_CHANNEL_REQUEST        = 98,   SSH_MSG_CHANNEL_SUCCESS           = 99,
              SSH_MSG_CHANNEL_FAILURE        = 100
};

enum CTXIDX { PACKET_LENGTH  = 0, PADDING_LENGTH  = 1, KEX_PACKT_TYPE = 2,
              CERTIFICATE_ID = 3, CERTIFICATE_B64 = 4, BN_EXPONENT    = 5,
              BN_MODULUS     = 6, BN_KEYF         = 7, PUBKEY_BLOB    = 8,
              SIGNATURE_ID   = 9, HASH_SIGNATURE  = 10, SERVER_COOKIE = 11
};

namespace tssh{

   struct sshKexPacket{
      uint32_t                  packet_length;
      uint8_t                   padding_length,
                                kex_packet_type,
                                kex_first_pkt_follow;
      std::vector<uint8_t>      server_cookie,
                                reserved;
      std::set<std::string>     algorithmStrings[10]; // | 0 - kex_algorithms  | 1 - srv_host_key_alg
                                                      // | 2 - enc_al_cl_srv   | 3 - enc_alg_srv_cl
                                                      // | 4 - mac_al_cl_srv   | 5 - mac_algs_srv_to_cl
                                                      // | 6 - cpr_alg_cl_srv  | 7 - cpr_algs_srv_to_cl
                                                      // | 8 - lang_cl_to_srv  | 9 - lang_srv_to_cl
   } ;

   using SshDhReplyPacket =  std::tuple< 
      uint32_t,              // PACKET_LENGTH   |
      uint8_t,               // PADDING_LENGTH  |
      uint8_t,               // KEX_PACKT_TYPE  |
   
      std::string,           // CERTIFICATE_ID  |   Certificate Type
      std::string,           // CERTIFICATE_B64 |   Certificate in B64 encoding
   
      BIGNUM*,               // BN_EXPONENT     |   Server PK Exponent
      BIGNUM*,               // BN_MODULUS      |   Server PK Modulus
      BIGNUM*,               // BN_KEYF         |   DH Server F
   
      std::vector<uint8_t>,  // PUBKEY_BLOB     |   Certificate ( Type + exp + mod)
      std::vector<uint8_t>,  // SIGNATURE_ID    |   SignatureIdentifier
      std::vector<uint8_t>,  // HASH_SIGNATURE  |   Hash Signature
      std::vector<uint8_t>   // SERVER_COOKIE   |   Server cookie 
   >;

   #ifdef __clang__
   #pragma clang diagnostic push
   #pragma clang diagnostic ignored "-Wweak-vtables"
   #endif

   class VarData{
      public:
         virtual void    appendData(std::vector<uint8_t>& dest)   = 0;
         virtual size_t  size(void)                               = 0;
         virtual         ~VarData(void)                           = 0;
   };

   #ifdef __clang__
   #pragma clang diagnostic pop
   #endif
   
   class VarDataBin : public VarData{
      public:
         explicit VarDataBin(std::vector<uint8_t>& val);
         void     appendData(std::vector<uint8_t>& dest)           anyexcept   override;
         size_t   size(void)                                       noexcept    override;
      private:
         std::vector<uint8_t>& data;
   };
   
   class VarDataChar : public VarData{
      public:
         explicit VarDataChar(char val);
         void     appendData(std::vector<uint8_t>& dest)           anyexcept   override;
         size_t   size(void)                                       noexcept    override;
      private:
         char data;
   };
   
   class VarDataUint32 : public VarData{
      public:
         explicit VarDataUint32(uint32_t val);
         void     appendData(std::vector<uint8_t>& dest)           anyexcept   override;
         size_t   size(void)                                       noexcept    override;
      private:
         uint32_t data;
   };
   
   template<class T>
   class VarDataString : public VarData{
      public:
         explicit VarDataString(T& val);
         void     appendData(std::vector<uint8_t>& dest)           anyexcept   override;
         size_t   size(void)                                       noexcept    override;
      private:
         T& data;
   };
   
   class VarDataCharArr : public VarData{
      public:
         explicit VarDataCharArr(const char* val);
                  ~VarDataCharArr(void)                                        override;
         void     appendData(std::vector<uint8_t>& dest)           anyexcept   override;
         size_t   size(void)                                       noexcept    override;
      private:
         const char* data; 
   };
   
   class VarDataRecursive : public VarData{
      public:
         explicit VarDataRecursive(std::initializer_list<VarData*>&& sList);
                  ~VarDataRecursive(void)                                      override;
         void     appendData(std::vector<uint8_t>& dest)           anyexcept   override;
         size_t   size(void)                                       noexcept    override;
      private:
         void     addSize(size_t len)                              noexcept;
         std::initializer_list<VarData*>  subList;
         size_t                           globalSize;
   };

   #ifdef __clang__
   #pragma clang diagnostic push
   #pragma clang diagnostic ignored "-Wweak-vtables"
   #endif
   class VarDataIn{
      public:
         virtual size_t  insertData(std::vector<uint8_t>& buff,
                                    size_t offset)                = 0;
         virtual         ~VarDataIn(void)                         = 0;
   };
   #ifdef __clang__
   #pragma clang diagnostic pop
   #endif

   template<class T>
   class VarDataBlob : public VarDataIn{
      public:
         VarDataBlob(T& dest, std::string dsc);
         size_t  insertData(std::vector<uint8_t>& buff,
                            size_t offset)                       anyexcept   override;
      private:
         T&               data;
         std::string      descr;
   };
   
   class VarDataBNum : public VarDataIn{
      public:
         VarDataBNum(BIGNUM* dest, std::string dsc);
         size_t  insertData(std::vector<uint8_t>& buff,
                            size_t offset)                       anyexcept   override;
      private:
         BIGNUM*          data; 
         std::string      descr;
   };
   
   using Key          = std::tuple<std::vector<uint8_t>, uint8_t, std::vector<uint8_t>>;
   using ClientPubKey = std::tuple<std::string, std::vector<uint8_t>, std::string>;
   using Id           = std::tuple<std::string, std::string, std::string>;
   
   class SshTransport : public inet::InetClient{
      public:
         SshTransport(std::string host, std::string port);
         ~SshTransport();
         void                   disconnect(void)                               anyexcept; 
   
      private:
         int                    rndFd;
         std::string            hostname, 
                                clientIdString,           
                                serverIdString;           
 
         mutable uint32_t       packetsRcvCount;   
         mutable uint32_t       packetsSndCount;
    
         sshKexPacket           clientConfiguration;
         SshDhReplyPacket       dhReplyPacket;
         std::vector<Key>       keys;   // Rows:                          |  Cols:
                                        // -------------------------------------------------
                                        // 0 - INITIAL_IV_C_TO_S_IDX      |  0 - KEYTEXT
                                        // 1 - INITIAL_IV_S_TO_C_IDX      |  1 - KEYTYPE
                                        // 2 - ENCR_KEY_C_TO_S_IDX        |  2 - KEYHASH
                                        // 3 - ENCR_KEY_S_TO_C_IDX        |
                                        // 4 - INTEGRITY_KEY_C_TO_S_IDX   |
                                        // 5 - INTEGRITY_KEY_S_TO_C_IDX   |
         bool                    haveKeys;
         std::vector<uint8_t>    clientKexInit,
                                 serverKexInit,
                                 sharedKey,
                                 currentSessionHash,  
                                 outcomingEnc,
                                 currentHashC,
                                 currentHashS,
                                 buffCopy;
      protected:
         crypto::Crypto          crypto;
         ClientPubKey            clientPubKey;
         std::vector<uint8_t>    sessionIdHash,
                                 incomingEnc,
                                 genericBuffer,
                                 message,
                                 partialRead; 
         unsigned int            currentHashCLen;
         size_t                  currentBlockLenE,
                                 currentBlockLenD;
         struct termios          termOld,
                                 termNew;
         std::string             knownHosts;

         void                   readSsh(void)                                            anyexcept; 
         bool                   readSshEnc(int chan=-1)                                  anyexcept; 
         void                   writeSsh(const uint8_t* msg, size_t size)         const  anyexcept; 
         void                   writeSsh(const std::string& msg)                  const  anyexcept;
         void                   writeSshEnc(std::vector<uint8_t>& msg, 
                                            uint8_t allign)                              anyexcept; 
         void                   checkSshHeader(void)                                     anyexcept; 
         void                   addRandomBytes(size_t  bytes, 
                                               std::vector<uint8_t>& target, 
                                               size_t offset)                     const  anyexcept; 
         std::vector<uint8_t>&  setKexMsg(void)                                          anyexcept; 
         void                   checkServerAlgList(void)                                 anyexcept; 
         void                   checkServerDhReply(void)                                 anyexcept; 
         void                   checkServerSignature(void)                               anyexcept; 
         void                   createKeys(size_t keyLen)                                anyexcept; 
         const std::string&     getServerId(void)                                 const  noexcept; 
         const std::string&     getClientId(void)                                 const  noexcept; 
         void                   getStatistics(void)                               const  noexcept; 
         void                   addHeader(uint8_t packetType,                        
                                          std::vector<uint8_t>& buff)             const  anyexcept; 
         void                   sendWithHeader(std::vector<uint8_t>& buff,
                                               uint8_t allign)                    const  anyexcept;
         void                   createSendPacket(const uint8_t packetType,
                                      std::initializer_list<VarData*>&& list)            anyexcept; 
   };

   using StatusTree  = std::map<unsigned int, std::set<unsigned int>>;

   class Fsm{
      private:
         unsigned int  currStat;
         StatusTree*   statuses;
      public:
         void                  setInitStat(unsigned int status)                          noexcept; 
         void                  setTree(StatusTree* tree)                                 noexcept; 
         void                  checkStatus(unsigned int newStat)                         anyexcept; 
   };
   
   class SshConnection : public  SshTransport{
      public:
         SshConnection(std::string& usr, std::string& host, std::string& port, 
                       bool noTerm, std::string& identity, uint32_t chan=0);
         ~SshConnection();
         void                    getShell()                                              anyexcept; 
      private:
         mutable
         volatile sig_atomic_t   sWinch;
         bool                    noTTY,
                                 nonCanonical;
         std::string             privKey,
                                 user,
                                 idFilePref,
                                 pubKey;
         uint32_t                channelNumber,
                                 remoteChannelNumber,
                                 initialWindowsSize,
                                 maxPacketSize,
                                 bytesToAdd;
         std::vector<uint8_t>    extData,
                                 keybInputData;
         struct winsize          windowAttr;
         struct sigaction        sigActionWndw;
         sigset_t                sigsetBackup,
                                 sigsetBlockAll;
         Fsm                     fsm;
   
         void                    getUserKeyFiles(void)                                   anyexcept; 
         void                    getUserPubK(void)                                       anyexcept; 
         void                    connectionLoop(void)                                    anyexcept; 
         void                    shellLoop(void)                                         anyexcept; 
         void                    shellLoopPty(void)                                      anyexcept; 
         void                    adjustWnwSize(void)                              const  noexcept; 
         void                    createAuthSign(std::vector<uint8_t>& msg, 
                                          std::initializer_list<VarData*>&& list)        anyexcept; 
         bool                    parseShellPacket(void)                                  anyexcept; 
         void                    createSendShellData()                                   anyexcept; 
   };

}

#endif
