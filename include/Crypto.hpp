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

#ifndef CRYPTO_LIB
#define CRYPTO_LIB

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif

#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#include <openssl/evp.h>

#include <string>
#include <vector>
#include <set>
#include <tuple>

#include <Types.hpp>
#include <StringUtils.hpp>

enum CRYPTOCFG { AES_BLOCK_LEN = 16, SHA1_DIGEST_LENGTH = 20, BYTE_LENGHT = 8};

static const char *RFC3526_PRIME    =  "0FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

namespace crypto {

   class  CryptoException final {
           public:
                   CryptoException(int errNum,
                                   std::string errString);
                   explicit    CryptoException(int errNum);
                   explicit    CryptoException(std::string&  errString);
                   explicit    CryptoException(std::string&& errString);
                   std::string what(void)                        const noexcept(true);
              private:
                   std::string errorMessage;
                   int errorCode;
   };

   #ifdef __clang__
   #pragma clang diagnostic push
   #pragma clang diagnostic ignored "-Wweak-vtables"
   #endif

   class CryptoDH{
      public: 
         virtual void      dhHash(std::vector<uint8_t>& buff,
                                  std::vector<uint8_t>& hash)    const = 0;
         virtual void      dhHash(std::vector<uint8_t>& buff,
                                  uint8_t*  hash)                const = 0;
         virtual size_t    getDhHashSize(void)                   const = 0;
         virtual           ~CryptoDH(void)                             = 0;
   };

   class CryptoDHG14Sha1 final : public CryptoDH{
      private:
         size_t      sha1Len;
      public: 
         CryptoDHG14Sha1(void);
         ~CryptoDHG14Sha1(void);
         void      dhHash(std::vector<uint8_t>& buff,
                          std::vector<uint8_t>& hash)           const noexcept(true)  override;
         void      dhHash(std::vector<uint8_t>& buff,
                          uint8_t* hash)                        const noexcept(true)  override;
         size_t    getDhHashSize(void)                          const noexcept(true)  override;
   };

   class CryptoHKeyAlg{
      public:   
         virtual               ~CryptoHKeyAlg(void)                           = 0;
         virtual void          setDhKeys(std::vector<uint8_t>& genBuff,
                                         std::vector<uint8_t>& res)           = 0;
         virtual void          signDH(std::vector<uint8_t>& buff,
                                      std::vector<uint8_t>& sign,
                                      BIGNUM* mod, BIGNUM* exp)         const = 0;
         virtual void          signMessage(std::string& privKey,
                                          std::vector<uint8_t>& msg, 
                                          std::vector<uint8_t>& sign)   const = 0;
         virtual void          setDhSharedKey(BIGNUM* f)                      = 0;              
         virtual const std::string&
                               getDhId(void)                            const = 0;              
         virtual const std::string&
                               getDhDescr(void)                         const = 0;              
         virtual BIGNUM*       getE(void)                               const = 0;
         virtual BIGNUM*       getSharedKey(void)                       const = 0;
         virtual const std::string&  
                               getKeyFilePrefix(void)                   const = 0;
         virtual const std::string&
                               getNullKey(void)                         const = 0;
   };

   class CryptoKeyRsa final : public CryptoHKeyAlg{
      private:
         BIGNUM               *bnSharedKey,
                              *bnPrivKey,
                              *bnPrime,
                              *bnE;
         BN_CTX               *ctx;
         const std::string    keyFilePrefix,                  
                              nullKey;                  
         const std::string    id;
         const std::string    descr;
      public: 
         CryptoKeyRsa(void);
         ~CryptoKeyRsa(void);
         void           setDhKeys(std::vector<uint8_t>& genBuff,
                                  std::vector<uint8_t>& res)          noexcept(false) override;
         void           signDH(std::vector<uint8_t>& buff,
                               std::vector<uint8_t>& sign,
                               BIGNUM* mod, BIGNUM* exp)        const noexcept(false) override;
         void           signMessage(std::string& privKey,
                                    std::vector<uint8_t>& msg, 
                                    std::vector<uint8_t>& sign) const noexcept(false) override;
         void           setDhSharedKey(BIGNUM* f)                     noexcept(false) override;
         const std::string&
                        getDhId(void)                           const noexcept(true)  override;
         const std::string&
                        getDhDescr(void)                        const noexcept(true)  override;
         BIGNUM*        getE(void)                              const noexcept(true)  override;
         BIGNUM*        getSharedKey(void)                      const noexcept(true)  override;
         const std::string&   
                        getKeyFilePrefix(void)                  const noexcept(true)  override;
         const std::string&   
                        getNullKey(void)                        const noexcept(true)  override;
   };
   
   class CryptoMacCtS{
      public:   
         virtual void init(std::vector<uint8_t>* initVect)             = 0; 
         virtual void hmac(const uint8_t* msg, int msize,
                           uint8_t* sign,
                           unsigned int* ssize)                  const = 0;
         virtual      ~CryptoMacCtS(void)                              = 0;
   };
   
   class CryptoMacCtSSha1 final : public CryptoMacCtS{ 
      private:
         std::vector<uint8_t>* iv;
      public:   
         void init(std::vector<uint8_t>* initVect)                    noexcept(true)  override;
         void hmac(const uint8_t* msg, int smsg,
                   uint8_t*  sign, unsigned int* ssize)         const noexcept(false) override;
   };
   
   class CryptoMacStC{
      public:   
         virtual void init(std::vector<uint8_t>* initVect)             = 0; 
         virtual void hmac(const uint8_t*  msg, int smsg,
                           uint8_t*  sign, 
                           unsigned int* ssize)                  const = 0;
         virtual      ~CryptoMacStC(void)                              = 0;
   };
   
   class CryptoMacStCSha1 final : public CryptoMacStC{
      private:
         std::vector<uint8_t>* iv;
      public:   
         void init(std::vector<uint8_t>* initVect)                    noexcept(true)  override;
         void hmac(const uint8_t*  msg, int smsg,
                   uint8_t*  sign, unsigned int* ssize)         const noexcept(false) override;
   };
   
   class CryptoBlkEncCtS{
      public:   
         virtual void    init(std::vector<uint8_t>& key, 
                              std::vector<uint8_t>& iv)                 = 0; 
         virtual void    encrUpd(uint8_t* msg, int  msize,
                                 uint8_t* encrypt, int* esize)   const  = 0;
         virtual void    encrFin(uint8_t* encrypt, int* esize)   const  = 0;
         virtual size_t  getBlockLen(void)                       const  = 0;
         virtual         ~CryptoBlkEncCtS(void)                         = 0;
   };
   
   class CryptoBlkEncCtSAes128Ctr final : public CryptoBlkEncCtS{
      private:
         EVP_CIPHER_CTX         *ectxE;
      public:   
         CryptoBlkEncCtSAes128Ctr(void);
         ~CryptoBlkEncCtSAes128Ctr(void);
         void    init(std::vector<uint8_t>& key, 
                      std::vector<uint8_t>& iv)                        noexcept(false) override;
         void    encrUpd(uint8_t* msg, int  msize,  
                         uint8_t* encrypt, int* esize)           const noexcept(false) override;
         void    encrFin(uint8_t* encrypt, int* esize)           const noexcept(false) override;
         size_t  getBlockLen(void)                               const noexcept(true)  override;
   };

   class CryptoBlkEncStC{
      public:   
         virtual void    init(std::vector<uint8_t>& key, 
                              std::vector<uint8_t>& iv)                  = 0; 
         virtual void    decrUpd(uint8_t* msg, int  msize,  
                                 uint8_t* decrypt, int* dsize)   const   = 0;
         virtual void    decrFin(uint8_t* decrypt, int* dsize)   const   = 0;
         virtual size_t  getBlockLen(void)                       const   = 0;
         virtual         ~CryptoBlkEncStC(void)                          = 0;
   };
   
   class CryptoBlkEncStCAes128Ctr final : public CryptoBlkEncStC{
      private:
         EVP_CIPHER_CTX         *ectxD;
      public:   
         CryptoBlkEncStCAes128Ctr(void);
         ~CryptoBlkEncStCAes128Ctr(void);
         void    init(std::vector<uint8_t>& key, 
                      std::vector<uint8_t>& iv)                       noexcept(false) override;
         void    decrUpd(uint8_t* msg, int  msize,  
                         uint8_t* decrypt, int* dsize)          const noexcept(false) override;
         void    decrFin(uint8_t* decrypt, int* dsize)          const noexcept(false) override;
         size_t  getBlockLen(void)                              const noexcept(true)  override;
   };

   #ifdef __clang__
   #pragma clang diagnostic pop
   #endif
 
   class Crypto final {
      private:
         CryptoDH*                        kexalg;
         CryptoHKeyAlg*                   hKeyalg;
         CryptoMacCtS*                    macCtS;
         CryptoMacStC*                    macStC;
         CryptoBlkEncCtS*                 blkEncCtS;
         CryptoBlkEncStC*                 blkEncStC;

         const std::vector<std::string>   clientHKeyAlg,
                                          clientKexAlg,
                                          clientMacCtSAlg,
                                          clientMacStCAlg,
                                          clientBlkEncStCAlg,
                                          clientBlkEncCtSAlg,
                                          clientComprCtSAlg,
                                          clientComprStCAlg,
                                          clientLangStC,
                                          clientLangCtS;

         const std::set<std::string>      *serverHKeyAlg,
                                          *serverKexAlg,
                                          *serverMacCtSAlg,
                                          *serverMacStCAlg,
                                          *serverBlkEncStCAlg,
                                          *serverBlkEncCtSAlg,
                                          *serverComprCtSAlg,
                                          *serverComprStCAlg,
                                          *serverLangStC,
                                          *serverLangCtS;

         std::string                      hKeyAlgsString,
                                          kexAlgsString,
                                          macAlgsCtSString,
                                          macAlgsStCString,
                                          blkAlgsStCString,
                                          blkAlgsCtSString,
                                          comprAlgsCtSString,
                                          comprAlgsStCString,
                                          langCtSString,
                                          langStCString;

         void setHKeyAlg(void)                                         noexcept(false);
         void setKexAlg(void)                                          noexcept(false);
         void setMacAlgCtS(void)                                       noexcept(false);
         void setMacAlgStC(void)                                       noexcept(false);
         void setBlkAlgStC(void)                                       noexcept(false);
         void setBlkAlgCtS(void)                                       noexcept(false);
         
      public:   
         Crypto(void);
         ~Crypto(void);
         void initServerAlgs(const std::set<std::string>* algorithmStrings)
                                                                       noexcept(false);
         const std::string& getHKeyAlgs(void)                    const noexcept(true);
         const std::string& getKexAlgs(void)                     const noexcept(true);
         const std::string& getMacAlgsCtS(void)                  const noexcept(true);
         const std::string& getMacAlgsStC(void)                  const noexcept(true);
         const std::string& getBlkAlgsCtS(void)                  const noexcept(true);
         const std::string& getBlkAlgsStC(void)                  const noexcept(true);
         const std::string& getComprAlgCtS(void)                 const noexcept(true);
         const std::string& getComprAlgStC(void)                 const noexcept(true);
         const std::string& getLangCtS(void)                     const noexcept(true);
         const std::string& getLangStC(void)                     const noexcept(true);

         void           setDhKeys(std::vector<uint8_t>& genBuff,
                                  std::vector<uint8_t>& res)           noexcept(false);
         void           dhHash(std::vector<uint8_t>& buff,
                               std::vector<uint8_t>& hash)       const noexcept(true);
         void           dhHash(std::vector<uint8_t>& buff,
                               uint8_t* hash)                    const noexcept(true);
         size_t         getDhHashSize(void)                      const noexcept(true);
         void           signDH(std::vector<uint8_t>& buff,
                               std::vector<uint8_t>& sign,
                               BIGNUM* mod, BIGNUM* exp)         const noexcept(false);
         void           signMessage(std::string& privKey,
                                    std::vector<uint8_t>& msg, 
                                    std::vector<uint8_t>& sign)  const noexcept(false);
         void           setDhSharedKey(BIGNUM* f)                      noexcept(false);
         BIGNUM*        getE(void)                               const noexcept(true);
         BIGNUM*        getSharedKey(void)                       const noexcept(true);
         const std::string&   
                        getKeyFilePrefix(void)                   const noexcept(true);
         const std::string&   
                        getNullKey(void)                         const noexcept(true);
         void           initMacCtS(std::vector<uint8_t>* 
                                   initVect)                           noexcept(true);
         void           hmacCtS(const uint8_t*  msg, int smsg,
                                uint8_t*  sign, 
                                unsigned int* ssize)             const noexcept(false);
         void           initMacStC(std::vector<uint8_t>*
                                   initVect)                           noexcept(true);
         void           hmacStC(const uint8_t*  msg, int smsg,
                                uint8_t* sign, 
                                unsigned int* ssize)             const noexcept(false);
         const std::string&
                        getDhId(void)                            const noexcept(true);
         const std::string&
                        getDhDescr(void)                         const noexcept(true);
         size_t         getBlockLenE(void)                       const noexcept(true);
         size_t         getBlockLenD(void)                       const noexcept(true);
         void           encr(uint8_t* msg, int  msize,
                             uint8_t* encrypt, int* esize)       const noexcept(false);
         void           encrFin(uint8_t* encrypt, int* esize)    const noexcept(false);
         void           decr(uint8_t* msg, int  msize,
                             uint8_t* decrypt, int* dsize)       const noexcept(false);
         void           decrFin(uint8_t* decrypt, int* dsize)    const noexcept(false);
         void           initBlkEnc(std::vector<uint8_t>& key, 
                                   std::vector<uint8_t>& iv)     const noexcept(false);
         void           initBlkDec(std::vector<uint8_t>& key, 
                                   std::vector<uint8_t>& iv)     const noexcept(false);
         template<class T>
         void           serverKeyHash(const T& in, 
                                   std::vector<uint8_t> &out)    const noexcept(false);
   };

   extern template 
   void Crypto::serverKeyHash(const std::string& in, 
                              std::vector<uint8_t>& out)         const noexcept(false);
}

#endif
