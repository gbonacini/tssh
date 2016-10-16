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

#include <Types.hpp>
#include <StringUtils.hpp>
#include <Inet.hpp>
#include <Crypto.hpp>

#define SSH_PORT                          "22"
#define COOKIE_LEN                        16
#define KEX_RESERVED_BYTES_LEN            4
#define PADDING_LEN_OFFSET                4
#define DATA_OFFSET                       6
#define PACKET_TYPE_OFFSET                5
#define BYTE_LENGHT                       8
 
#define SSH_RSA_MIN_MODULUS_LENGTH        768
#define SSH_MAX_PACKET_SIZE               35000
#define SSH_MAX_ID_STRING_SIZE            255
#define SSH_STD_KEYS_NUMBER               6
#define SSH_CONF_DIRECTORY                ".ssh"
#define SSH_KNOWN_HOST_FILE               "known_hosts"
#define SSH_PTY_ECHO                      53
#define SSH_DEFAULT_TERM                  "vt100"
#define SSH_PTY_REQ                       "pty-req"
#define SSH_SHELL_REQ                     "shell"

#define INITIAL_IV_C_TO_S                  'A'
#define INITIAL_IV_S_TO_C                  'B'
#define ENCR_KEY_C_TO_S                    'C'
#define ENCR_KEY_S_TO_C                    'D'
#define INTEGRITY_KEY_C_TO_S               'E'
#define INTEGRITY_KEY_S_TO_C               'F'

#define INITIAL_IV_C_TO_S_IDX               0
#define INITIAL_IV_S_TO_C_IDX               1
#define ENCR_KEY_C_TO_S_IDX                 2
#define ENCR_KEY_S_TO_C_IDX                 3
#define INTEGRITY_KEY_C_TO_S_IDX            4
#define INTEGRITY_KEY_S_TO_C_IDX            5
 
#define KEYTEXT                             0
#define KEYTYPE                             1
#define KEYHASH                             2

#define PUBKEYTYPE                          0
#define PUBKEYBLOB                          1
#define PUBKEYUSR                           2

#define BEGINNING_BLOCK_LEN_ALLIGN          8
#define AES_BLOCK_LEN                       16
#define AES_BLOCK_LEN_ALLIGN                64

#define SSH_ID_STRING                       "SSH-2.0-bg\r\n"
#define SSH_HEADER_ID                       "SSH-2.0"
#define RAND_FILE                           "/dev/urandom"

#define SSH_CONN_START                      0
#define SSH_MSG_DISCONNECT                  1
#define SSH_MSG_IGNORE                      2
#define SSH_MSG_UNIMPLEMENTED               3
#define SSH_DISCONNECT_BY_APPLICATION       11

#define SSH_MSG_SERVICE_REQUEST             5
#define SSH_MSG_SERVICE_ACCEPT              6

#define SSH_MSG_KEXINIT                     20
#define SSH_MSG_NEWKEYS                     21
#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD      30

#define SSH_MSG_USERAUTH_REQUEST            50
#define SSH_MSG_USERAUTH_FAILURE            51
#define SSH_MSG_USERAUTH_SUCCESS            52
#define SSH_MSG_USERAUTH_BANNER             53

//      SSH_MSG_USERAUTH_PK_OK              60
#define SSH_MSG_USERAUTH_INFO_REQUEST       60
#define SSH_MSG_USERAUTH_INFO_RESPONSE      61

#define SSH_MSG_GLOBAL_REQUEST              80
// #define SSH_MSG_REQUEST_SUCCESS          81
#define SSH_MSG_REQUEST_FAILURE             82

#define SSH_MSG_CHANNEL_OPEN                90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION   91
#define SSH_MSG_CHANNEL_OPEN_FAILURE        92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST       93
#define SSH_MSG_CHANNEL_DATA                94
#define SSH_MSG_CHANNEL_EXTENDED_DATA       95
#define SSH_MSG_CHANNEL_EOF                 96
#define SSH_MSG_CHANNEL_CLOSE               97
#define SSH_MSG_CHANNEL_REQUEST             98
#define SSH_MSG_CHANNEL_SUCCESS             99
#define SSH_MSG_CHANNEL_FAILURE             100

#define SSH_USERAUTH_STRING                 "ssh-userauth"
#define SSH_CONNECT_STRING                  "ssh-connection"
#define SSH_PUBKEY_AUTH_REQ                 "publickey"
#define SSH_PASSWD_SPEC                     "password"
#define SSH_KEYB_INTER_SPEC                 "keyboard-interactive"
#define SSH_SESSION_SPEC                    "session"
#define SSH_WNDW_RESIZE                     "window-change"

#define CHANNEL_EXTDATA_STDERR              1

#define   PACKET_LENGTH                     0
#define   PADDING_LENGTH                    1
#define   KEX_PACKT_TYPE                    2
#define   CERTIFICATE_ID                    3
#define   CERTIFICATE_B64                   4
#define   BN_EXPONENT                       5
#define   BN_MODULUS                        6
#define   BN_KEYF                           7
#define   PUBKEY_BLOB                       8
#define   SIGNATURE_ID                      9
#define   HASH_SIGNATURE                    10
#define   SERVER_COOKIE                     11

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

   typedef std::tuple< 
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
   >  SshDhReplyPacket;

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
         VarDataBin(std::vector<uint8_t>& val);
         void    appendData(std::vector<uint8_t>& dest)           noexcept(false)   override;
         size_t  size(void)                                       noexcept(true)    override;
      private:
         std::vector<uint8_t>& data;
   };
   
   class VarDataChar : public VarData{
      public:
         VarDataChar(char val);
         void    appendData(std::vector<uint8_t>& dest)           noexcept(false)   override;
         size_t  size(void)                                       noexcept(true)    override;
      private:
         char data;
   };
   
   class VarDataUint32 : public VarData{
      public:
         VarDataUint32(uint32_t val);
         void    appendData(std::vector<uint8_t>& dest)           noexcept(false)   override;
         size_t  size(void)                                       noexcept(true)    override;
      private:
         uint32_t data;
   };
   
   template<class T>
   class VarDataString : public VarData{
      public:
         VarDataString(T& val);
         void    appendData(std::vector<uint8_t>& dest)           noexcept(false)   override;
         size_t  size(void)                                       noexcept(true)    override;
      private:
         T& data;
   };
   
   class VarDataCharArr : public VarData{
      public:
         VarDataCharArr(const char* val);
         ~VarDataCharArr(void);
         void    appendData(std::vector<uint8_t>& dest)           noexcept(false)   override;
         size_t  size(void)                                       noexcept(true)    override;
      private:
         const char* data; 
   };
   
   class VarDataRecursive : public VarData{
      public:
         VarDataRecursive(std::initializer_list<VarData*> sList);
         ~VarDataRecursive(void);
         void    appendData(std::vector<uint8_t>& dest)           noexcept(false)   override;
         size_t  size(void)                                       noexcept(true)    override;
      private:
         void                             addSize(size_t len)     noexcept(true);
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
                            size_t offset)                       noexcept(false)   override;
      private:
         T&               data;
         std::string      descr;
   };
   
   class VarDataBNum : public VarDataIn{
      public:
         VarDataBNum(BIGNUM* dest, std::string dsc);
         size_t  insertData(std::vector<uint8_t>& buff,
                            size_t offset)                       noexcept(false)   override;
      private:
         BIGNUM*          data; 
         std::string      descr;
   };
   
   typedef std::tuple<std::vector<uint8_t>, uint8_t, std::vector<uint8_t> >    Key;
   typedef std::tuple<std::string, std::vector<uint8_t>, std::string>          ClientPubKey;
   typedef std::tuple<std::string, std::string, std::string >                  Id;
   
   class SshTransport : public inet::InetClient{
      public:
         SshTransport(std::string host, std::string port);
         ~SshTransport();
         void                   disconnect(void)                               noexcept(false); 
   
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

         void                   readSsh(void)                                            noexcept(false); 
         bool                   readSshEnc(int chan=-1)                                  noexcept(false); 
         void                   writeSsh(const uint8_t* msg, size_t size)         const  noexcept(false); 
         void                   writeSsh(const std::string& msg)                  const  noexcept(false);
         void                   writeSshEnc(std::vector<uint8_t>& msg, 
                                            uint8_t allign)                              noexcept(false); 
         void                   checkSshHeader(void)                                     noexcept(false); 
         void                   addRandomBytes(size_t  bytes, 
                                               std::vector<uint8_t>& target, 
                                               size_t offset)                     const  noexcept(false); 
         std::vector<uint8_t>&  setKexMsg(void)                                          noexcept(false); 
         void                   checkServerAlgList(void)                                 noexcept(false); 
         void                   checkServerDhReply(void)                                 noexcept(false); 
         void                   checkServerSignature(void)                               noexcept(false); 
         void                   createKeys(size_t keyLen)                                noexcept(false); 
         const std::string&     getServerId(void)                                 const  noexcept(true); 
         const std::string&     getClientId(void)                                 const  noexcept(true); 
         void                   getStatistics(void)                               const  noexcept(true); 
         void                   addHeader(uint8_t packetType,                        
                                          std::vector<uint8_t>& buff)             const  noexcept(false); 
         void                   sendWithHeader(std::vector<uint8_t>& buff,
                                               uint8_t allign)                    const  noexcept(false);
         void                   createSendPacket(const uint8_t packetType,
                                      std::initializer_list<VarData*> list)              noexcept(false); 
   };

   typedef std::map<unsigned int, std::set<unsigned int>> StatusTree;

   class Fsm{
      private:
         unsigned int  currStat;
         StatusTree*   statuses;
      public:
         void                  setInitStat(unsigned int status)                          noexcept(true); 
         void                  setTree(StatusTree* tree)                                 noexcept(true); 
         void                  checkStatus(unsigned int newStat)                         noexcept(false); 
   };
   
   class SshConnection : public  SshTransport{
      public:
         SshConnection(std::string& usr, std::string& host, std::string& port, 
                       bool noTerm, std::string& identity, uint32_t chan=0);
         ~SshConnection();
         void                    getShell()                                              noexcept(false); 
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
   
         void                    getUserKeyFiles(void)                                   noexcept(false); 
         void                    getUserPubK(void)                                       noexcept(false); 
         void                    connectionLoop(void)                                    noexcept(false); 
         void                    shellLoop(void)                                         noexcept(false); 
         void                    shellLoopPty(void)                                      noexcept(false); 
         void                    adjustWnwSize(void)                              const  noexcept(true); 
         void                    createAuthSign(std::vector<uint8_t>& msg, 
                                          std::initializer_list<VarData*> list)          noexcept(false); 
         bool                    parseShellPacket(void)                                  noexcept(false); 
         void                    createSendShellData()                                   noexcept(false); 
   };

}

#endif
