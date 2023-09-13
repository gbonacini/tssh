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

#ifndef CRYPTO_LIB
#define CRYPTO_LIB

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#pragma clang diagnostic ignored "-Wold-style-cast"
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

#include <exception>
#include <string>
#include <vector>
#include <set>
#include <tuple>

#include <anyexcept.hpp>
#include <Types.hpp>
#include <StringUtils.hpp>

enum CRYPTOCFG { AES_BLOCK_LEN        = 16, 
                 SHA1_DIGEST_LENGTH   = 20, 
                 BYTE_LENGHT          = 8};

namespace crypto {

   class  CryptoException final : std::exception {
           public :
                   CryptoException(int errNum,
                                   std::string errString);
                   explicit    CryptoException(int errNum);
                   explicit    CryptoException(std::string&  errString);
                   explicit    CryptoException(std::string&& errString);
                   const char* what(void)                        const noexcept override;
                   int         getErrorCode(void)                const noexcept;
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
         ~CryptoDHG14Sha1(void)                                                 override;
         void      dhHash(std::vector<uint8_t>& buff,
                          std::vector<uint8_t>& hash)           const noexcept  override;
         void      dhHash(std::vector<uint8_t>& buff,
                          uint8_t* hash)                        const noexcept  override;
         size_t    getDhHashSize(void)                          const noexcept  override;
   };

   class CryptoDHG14Sha256 final : public CryptoDH{
      private:
         size_t      sha256Len;
      public: 
         CryptoDHG14Sha256(void);
         ~CryptoDHG14Sha256(void)                                               override;
         void      dhHash(std::vector<uint8_t>& buff,
                          std::vector<uint8_t>& hash)           const noexcept  override;
         void      dhHash(std::vector<uint8_t>& buff,
                          uint8_t* hash)                        const noexcept  override;
         size_t    getDhHashSize(void)                          const noexcept  override;
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

   class CryptoKeyRsa : public CryptoHKeyAlg{
      protected:
         BIGNUM               *bnSharedKey,
                              *bnPrivKey,
                              *bnPrime,
                              *bnE;
         BN_CTX               *ctx;
         const std::string    keyFilePrefix,                  
                              nullKey,                  
                              id,
                              descr;

      public: 
         CryptoKeyRsa(std::string ids="rsa-ssh");
         ~CryptoKeyRsa(void)                                                    override;
         void           setDhKeys(std::vector<uint8_t>& genBuff,
                                  std::vector<uint8_t>& res)          anyexcept override;
         void           signDH(std::vector<uint8_t>& buff,
                               std::vector<uint8_t>& sign,
                               BIGNUM* mod, BIGNUM* exp)        const anyexcept override;
         void           signMessage(std::string& privKey,
                                    std::vector<uint8_t>& msg, 
                                    std::vector<uint8_t>& sign) const anyexcept override;
         void           setDhSharedKey(BIGNUM* f)                     anyexcept override;
         const std::string&
                        getDhId(void)                           const noexcept  override;
         const std::string&
                        getDhDescr(void)                        const noexcept  override;
         BIGNUM*        getE(void)                              const noexcept  override;
         BIGNUM*        getSharedKey(void)                      const noexcept  override;
         const std::string&   
                        getKeyFilePrefix(void)                  const noexcept  override;
         const std::string&   
                        getNullKey(void)                        const noexcept  override;
   };

   class CryptoKeyRsa2_256 final : public CryptoKeyRsa{
      public: 
         CryptoKeyRsa2_256( std::string ids="rsa-sha2-256");
         ~CryptoKeyRsa2_256(void)                                               override;
                                  
         void           signDH(std::vector<uint8_t>& buff,
                               std::vector<uint8_t>& sign,
                               BIGNUM* mod, BIGNUM* exp)        const anyexcept override;

         void           signMessage(std::string& privKey,
                                    std::vector<uint8_t>& msg, 
                                    std::vector<uint8_t>& sign) const anyexcept override;

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
         void init(std::vector<uint8_t>* initVect)                    noexcept  override;
         void hmac(const uint8_t* msg, int smsg,
                   uint8_t*  sign, unsigned int* ssize)         const anyexcept override;
   };
   
   class CryptoMacCtSSha256 final : public CryptoMacCtS{ 
      private:
         std::vector<uint8_t>* iv;
      public:   
         void init(std::vector<uint8_t>* initVect)                    noexcept  override;
         void hmac(const uint8_t* msg, int smsg,
                   uint8_t*  sign, unsigned int* ssize)         const anyexcept override;
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
         void init(std::vector<uint8_t>* initVect)                    noexcept  override;
         void hmac(const uint8_t*  msg, int smsg,
                   uint8_t*  sign, unsigned int* ssize)         const anyexcept override;
   };
   
   class CryptoMacStCSha256 final : public CryptoMacStC{
      private:
         std::vector<uint8_t>* iv;
      public:   
         void init(std::vector<uint8_t>* initVect)                    noexcept  override;
         void hmac(const uint8_t*  msg, int smsg,
                   uint8_t*  sign, unsigned int* ssize)         const anyexcept override;
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
         ~CryptoBlkEncCtSAes128Ctr(void)                                         override;
         void    init(std::vector<uint8_t>& key, 
                      std::vector<uint8_t>& iv)                        anyexcept override;
         void    encrUpd(uint8_t* msg, int  msize,  
                         uint8_t* encrypt, int* esize)           const anyexcept override;
         void    encrFin(uint8_t* encrypt, int* esize)           const anyexcept override;
         size_t  getBlockLen(void)                               const noexcept  override;
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
         ~CryptoBlkEncStCAes128Ctr(void)                                        override;
         void    init(std::vector<uint8_t>& key, 
                      std::vector<uint8_t>& iv)                       anyexcept override;
         void    decrUpd(uint8_t* msg, int  msize,  
                         uint8_t* decrypt, int* dsize)          const anyexcept override;
         void    decrFin(uint8_t* decrypt, int* dsize)          const anyexcept override;
         size_t  getBlockLen(void)                              const noexcept  override;
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

         void   setHKeyAlg(void)                                        anyexcept;
         size_t setKexAlg(void)                                         anyexcept;
         void   setMacAlgCtS(size_t idx)                                anyexcept;
         void   setMacAlgStC(size_t idx)                                anyexcept;
         void   setBlkAlgStC(void)                                      anyexcept;
         void   setBlkAlgCtS(void)                                      anyexcept;
         
      public:   
         Crypto(void);
         ~Crypto(void);
         void initServerAlgs(const std::set<std::string>* algorithmStrings)
                                                                       anyexcept;
         const std::string& getHKeyAlgs(void)                    const noexcept;
         const std::string& getKexAlgs(void)                     const noexcept;
         const std::string& getMacAlgsCtS(void)                  const noexcept;
         const std::string& getMacAlgsStC(void)                  const noexcept;
         const std::string& getBlkAlgsCtS(void)                  const noexcept;
         const std::string& getBlkAlgsStC(void)                  const noexcept;
         const std::string& getComprAlgCtS(void)                 const noexcept;
         const std::string& getComprAlgStC(void)                 const noexcept;
         const std::string& getLangCtS(void)                     const noexcept;
         const std::string& getLangStC(void)                     const noexcept;

         void           setDhKeys(std::vector<uint8_t>& genBuff,
                                  std::vector<uint8_t>& res)           anyexcept;
         void           dhHash(std::vector<uint8_t>& buff,
                               std::vector<uint8_t>& hash)       const noexcept;
         void           dhHash(std::vector<uint8_t>& buff,
                               uint8_t* hash)                    const noexcept;
         size_t         getDhHashSize(void)                      const noexcept;
         void           signDH(std::vector<uint8_t>& buff,
                               std::vector<uint8_t>& sign,
                               BIGNUM* mod, BIGNUM* exp)         const anyexcept;
         void           signMessage(std::string& privKey,
                                    std::vector<uint8_t>& msg, 
                                    std::vector<uint8_t>& sign)  const anyexcept;
         void           setDhSharedKey(BIGNUM* f)                      anyexcept;
         BIGNUM*        getE(void)                               const noexcept;
         BIGNUM*        getSharedKey(void)                       const noexcept;
         const std::string&   
                        getKeyFilePrefix(void)                   const noexcept;
         const std::string&   
                        getNullKey(void)                         const noexcept;
         void           initMacCtS(std::vector<uint8_t>* 
                                   initVect)                           noexcept;
         void           hmacCtS(const uint8_t*  msg, int smsg,
                                uint8_t*  sign, 
                                unsigned int* ssize)             const anyexcept;
         void           initMacStC(std::vector<uint8_t>*
                                   initVect)                           noexcept;
         void           hmacStC(const uint8_t*  msg, int smsg,
                                uint8_t* sign, 
                                unsigned int* ssize)             const anyexcept;
         const std::string&
                        getDhId(void)                            const noexcept;
         const std::string&
                        getDhDescr(void)                         const noexcept;
         size_t         getBlockLenE(void)                       const noexcept;
         size_t         getBlockLenD(void)                       const noexcept;
         void           encr(uint8_t* msg, int  msize,
                             uint8_t* encrypt, int* esize)       const anyexcept;
         void           encrFin(uint8_t* encrypt, int* esize)    const anyexcept;
         void           decr(uint8_t* msg, int  msize,
                             uint8_t* decrypt, int* dsize)       const anyexcept;
         void           decrFin(uint8_t* decrypt, int* dsize)    const anyexcept;
         void           initBlkEnc(std::vector<uint8_t>& key, 
                                   std::vector<uint8_t>& iv)     const anyexcept;
         void           initBlkDec(std::vector<uint8_t>& key, 
                                   std::vector<uint8_t>& iv)     const anyexcept;
         template<class T>
         void           serverKeyHash(const T& in, 
                                   std::vector<uint8_t> &out)    const anyexcept;
   };

   extern template 
   void Crypto::serverKeyHash(const std::string& in, 
                              std::vector<uint8_t>& out)         const anyexcept;
}

#endif
