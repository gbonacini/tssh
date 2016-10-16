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


#include <Crypto.hpp>

namespace crypto{

   using std::string;
   using std::to_string;
   using std::vector;
   using std::set;
   using std::get;
   using std::initializer_list;

   using stringutils::trace;
   using stringutils::getDebug;
   using stringutils::encodeB64;
   using stringutils::appendVectBuffer;
   using stringutils::encodeHex;
   using stringutils::secureZeroing;
   using stringutils::loadFileMem;
   using stringutils::StringUtilsException;

   using typeutils::safeInt;
   using typeutils::safeSizeT;

   CryptoException::CryptoException(int errNum){
           errorCode=errNum;
           errorMessage="None";
   }

   CryptoException::CryptoException(string errString){
           errorMessage=errString;
           errorCode=0;
   }

   CryptoException::CryptoException(int errNum, string errString){
           errorMessage=errString;
           errorCode=errNum;
   }

   string CryptoException::what() const noexcept(true){
           return errorMessage;
   }

   CryptoDH::~CryptoDH(){ }

   #if defined  __clang_major__ && !defined __APPLE__ && __clang_major__ >= 4 
   #pragma clang diagnostic push 
   #pragma clang diagnostic ignored "-Wundefined-func-template"
   #endif

   CryptoHKeyAlg::~CryptoHKeyAlg(){ }

   Crypto::Crypto(void) :
      kexalg(nullptr),  hKeyalg(nullptr),    macCtS(nullptr),  
      macStC(nullptr),  blkEncCtS(nullptr),  blkEncStC(nullptr),
      clientHKeyAlg        { "ssh-rsa" },
      clientKexAlg         { "diffie-hellman-group14-sha1" },
      clientMacCtSAlg      { "hmac-sha1" },
      clientMacStCAlg      { "hmac-sha1" },
      clientBlkEncStCAlg   { "aes128-ctr" },
      clientBlkEncCtSAlg   { "aes128-ctr" },
      clientComprCtSAlg    { "none" },
      clientComprStCAlg    { "none" },
      clientLangStC        { "" },
      clientLangCtS        { "" } 
   {
      OpenSSL_add_all_algorithms();
      SSL_load_error_strings();

      for(auto i=clientHKeyAlg.begin(); i!=clientHKeyAlg.end(); ++i){
         hKeyAlgsString.append(*i);
         if(i != clientHKeyAlg.end() - 1) hKeyAlgsString.append(",");
      }
      for(auto i=clientKexAlg.begin(); i!=clientKexAlg.end(); ++i){
         kexAlgsString.append(*i);
         if(i != clientKexAlg.end() - 1) kexAlgsString.append(",");
      }
      for(auto i=clientMacCtSAlg.begin(); i!=clientMacCtSAlg.end(); ++i){
         macAlgsCtSString.append(*i);
         if(i != clientMacCtSAlg.end() - 1) macAlgsCtSString.append(",");
      }
      for(auto i=clientMacStCAlg.begin(); i!=clientMacStCAlg.end(); ++i){
         macAlgsStCString.append(*i);
         if(i != clientMacStCAlg.end() - 1) macAlgsStCString.append(",");
      }
      for(auto i=clientBlkEncStCAlg.begin(); i!=clientBlkEncStCAlg.end(); ++i){
         blkAlgsStCString.append(*i);
         if(i != clientBlkEncStCAlg.end() - 1) blkAlgsStCString.append(",");
      }
      for(auto i=clientBlkEncCtSAlg.begin(); i!=clientBlkEncCtSAlg.end(); ++i){
         blkAlgsCtSString.append(*i);
         if(i != clientBlkEncCtSAlg.end() - 1) blkAlgsCtSString.append(",");
      }
      for(auto i=clientComprCtSAlg.begin(); i!=clientComprCtSAlg.end(); ++i){
         comprAlgsCtSString.append(*i);
         if(i != clientComprCtSAlg.end() - 1) comprAlgsCtSString.append(",");
      }
      for(auto i=clientComprStCAlg.begin(); i!=clientComprStCAlg.end(); ++i){
         comprAlgsStCString.append(*i);
         if(i != clientComprStCAlg.end() - 1) comprAlgsStCString.append(",");
      }
      for(auto i=clientLangStC.begin(); i!=clientLangStC.end(); ++i){
         langCtSString.append(*i);
         if(i != clientLangStC.end() - 1) langCtSString.append(",");
      }
      for(auto i=clientLangCtS.begin(); i!=clientLangCtS.end(); ++i){
         langStCString.append(*i);
         if(i != clientLangCtS.end() - 1) langStCString.append(",");
      }
     
   }

   void Crypto::initServerAlgs(const set<string>*  algorithmStrings) noexcept(false){
      // | 0 - kex_algorithms  | 1 - srv_host_key_alg
      // | 2 - enc_al_cl_srv   | 3 - enc_alg_srv_cl
      // | 4 - mac_al_cl_srv   | 5 - mac_algs_srv_to_cl
      // | 6 - cpr_alg_cl_srv  | 7 - cpr_algs_srv_to_cl
      // | 8 - lang_cl_to_srv  | 9 - lang_srv_to_cl

      serverKexAlg           = algorithmStrings;
      serverHKeyAlg          = algorithmStrings + 1;
      serverBlkEncCtSAlg     = algorithmStrings + 2;
      serverBlkEncStCAlg     = algorithmStrings + 3;
      serverMacCtSAlg        = algorithmStrings + 4;
      serverMacStCAlg        = algorithmStrings + 5;
      serverComprCtSAlg      = algorithmStrings + 6;
      serverComprStCAlg      = algorithmStrings + 7;
      serverLangCtS          = algorithmStrings + 8;
      serverLangStC          = algorithmStrings + 9;

      setHKeyAlg();
      setKexAlg();
      setMacAlgCtS();
      setMacAlgStC();
      setBlkAlgStC();
      setBlkAlgCtS();
   }

   Crypto::~Crypto(void){
      if(kexalg != nullptr)     delete kexalg;
      if(hKeyalg != nullptr)    delete hKeyalg;
      if(macCtS != nullptr)     delete macCtS;
      if(macStC != nullptr)     delete macStC;
      if(blkEncCtS != nullptr)  delete blkEncCtS;
      if(blkEncStC != nullptr)  delete blkEncStC;

      EVP_cleanup();
      ERR_free_strings();
      ERR_remove_state(0);

      CRYPTO_cleanup_all_ex_data();
   }

   const string& Crypto::getHKeyAlgs(void)    const noexcept(true){
      return hKeyAlgsString;
   }

   const string& Crypto::getKexAlgs(void)    const noexcept(true){
      return kexAlgsString;
   }

   const string& Crypto::getKeyFilePrefix(void) const noexcept(true){
      return hKeyalg->getKeyFilePrefix();
   }

   const string& Crypto::getNullKey(void) const noexcept(true){
      return hKeyalg->getNullKey();
   }

   const string& Crypto::getMacAlgsCtS(void) const noexcept(true){
      return macAlgsCtSString;
   }

   const string& Crypto::getMacAlgsStC(void) const noexcept(true){
      return macAlgsStCString;
   }

   const string& Crypto::getBlkAlgsStC(void) const noexcept(true){
      return blkAlgsStCString;
   }

   const string& Crypto::getBlkAlgsCtS(void) const noexcept(true){
      return blkAlgsCtSString;
   }

   const string& Crypto::getComprAlgCtS(void) const noexcept(true){
      return comprAlgsCtSString;
   }

   const string& Crypto::getComprAlgStC(void) const noexcept(true){
      return comprAlgsStCString;
   }

   const string& Crypto::getLangCtS(void) const noexcept(true){
      return langCtSString;
   }

   const string& Crypto::getLangStC(void) const noexcept(true){
      return langStCString;
   }

   void Crypto::dhHash(vector<uint8_t>& buff, vector<uint8_t>& hash) const noexcept(true){
      kexalg->dhHash(buff, hash);
   }

   void Crypto::dhHash(vector<uint8_t>& buff, uint8_t* hash) const noexcept(true){
      kexalg->dhHash(buff, hash);
   }

   size_t Crypto::getDhHashSize(void) const noexcept(true){
      return kexalg->getDhHashSize();
   }

   void Crypto::setDhKeys(vector<uint8_t>& genBuff, vector<uint8_t>& res) noexcept(false){
      hKeyalg->setDhKeys(genBuff, res);
   }

   void Crypto::signDH(vector<uint8_t>& buff, vector<uint8_t>& sign,
                       BIGNUM* mod, BIGNUM* exp) const noexcept(false){
      hKeyalg->signDH(buff, sign, mod, exp);
   }

   void Crypto::signMessage(std::string& privKey, std::vector<uint8_t>& msg,
                            std::vector<uint8_t>& sign) const noexcept(false){
      hKeyalg->signMessage(privKey, msg, sign);
   }

   void Crypto::setHKeyAlg(void)  noexcept(false){
      bool    found = false;
      size_t  idx   = 0;
      for(auto i = clientHKeyAlg.begin(); i != clientHKeyAlg.end(); ++i){
         if(serverHKeyAlg->find(*i) != serverHKeyAlg->end()){
		found  = true;
                break;
         }
         idx++;
      }
      if(!found)
         throw CryptoException("setHKeyAlg: Unexpected key type.");

     switch(idx){
        case 0:
           hKeyalg = new CryptoKeyRsa();
           TRACE("* DH Selected: diffie-hellman-group14-sha1");
        break;
        default:
           throw CryptoException("setHKeyAlg: key type error.");
     }
   }

   const std::string& Crypto::getDhId(void) const noexcept(true){ 
      return hKeyalg->getDhId();;
   }

   const std::string& Crypto::getDhDescr(void) const noexcept(true){ 
      return hKeyalg->getDhDescr();;
   }

   BIGNUM* Crypto::getE(void) const noexcept(true){
      return hKeyalg->getE();
   }

   BIGNUM* Crypto::getSharedKey(void) const noexcept(true){
      return hKeyalg->getSharedKey();
   }

   void Crypto::setDhSharedKey(BIGNUM* f) noexcept(false){
      hKeyalg->setDhSharedKey(f);
   }

   void Crypto::setKexAlg(void)     noexcept(false){
      bool    found = false;
      size_t  idx   = 0;
      for(auto i = clientKexAlg.begin(); i != clientKexAlg.end(); ++i){
         if(serverKexAlg->find(*i) != serverKexAlg->end()){
		found  = true;
                break;
         }
         idx++;
      }
      if(!found)
         throw CryptoException("setKexAlg: Unexpected algorithm in DH kex packet.");

     switch(idx){
        case 0:
           kexalg = new CryptoDHG14Sha1();
           TRACE("* DH Selected: diffie-hellman-group14-sha1");
        break;
        default:
           throw CryptoException("setKexAlg: Unsupported DH algorithm.");
     }
   }

   void Crypto::setMacAlgCtS(void)  noexcept(false){
      bool    found = false;
      size_t  idx   = 0;
      for(auto i = clientMacCtSAlg.begin(); i != clientMacCtSAlg.end(); ++i){
         if(serverMacCtSAlg->find(*i) != serverMacCtSAlg->end()){
		found  = true;
                break;
         }
         idx++;
      }
      if(!found)
         throw CryptoException("setMacAlgCtS: Unexpected CtS MAC type.");

     switch(idx){
        case 0:
           macCtS = new CryptoMacCtSSha1();
           TRACE("* MAC CtS Selected: hmac-sha1");
        break;
        default:
           throw CryptoException("setMacAlgCtS: MAC CtS type error.");
     }
   }

   void Crypto::setMacAlgStC(void)  noexcept(false){
      bool    found = false;
      size_t  idx   = 0;
      for(auto i = clientMacStCAlg.begin(); i != clientMacStCAlg.end(); ++i){
         if(serverMacStCAlg->find(*i) != serverMacStCAlg->end()){
		found  = true;
                break;
         }
         idx++;
      }
      if(!found)
         throw CryptoException("setMacAlgStC: Unexpected StC MAC type.");

     switch(idx){
        case 0:
           macStC = new CryptoMacStCSha1();
           TRACE("* Block Cipher StC Selected: hmac-sha1");
        break;
        default:
           throw CryptoException("setMacAlgStC: Block Cipher StC type error.");
     }
   }

   CryptoBlkEncCtS::~CryptoBlkEncCtS(void){}

   CryptoBlkEncStC::~CryptoBlkEncStC(void){}

   void Crypto::setBlkAlgCtS(void)  noexcept(false){
      bool    found = false;
      size_t  idx   = 0;
      for(auto i = clientBlkEncCtSAlg.begin(); i != clientBlkEncCtSAlg.end(); ++i){
         if(serverBlkEncCtSAlg->find(*i) != serverBlkEncCtSAlg->end()){
		found  = true;
                break;
         }
         idx++;
      }
      if(!found)
         throw CryptoException("setBlkAlgCtS: Unexpected CtS Block Cipher type.");

     switch(idx){
        case 0:
           blkEncCtS = new CryptoBlkEncCtSAes128Ctr();
           TRACE("* MAC CtS Selected: hmac-sha1");
        break;
        default:
           throw CryptoException("setBlkAlgCtS: MAC CtS type error.");
     }
   }

   void Crypto::setBlkAlgStC(void)  noexcept(false){
      bool    found = false;
      size_t  idx   = 0;
      for(auto i = clientBlkEncStCAlg.begin(); i != clientBlkEncStCAlg.end(); ++i){
         if(serverBlkEncStCAlg->find(*i) != serverBlkEncStCAlg->end()){
		found  = true;
                break;
         }
         idx++;
      }
      if(!found)
         throw CryptoException("setBlkAlgStC: Unexpected StC Block Cipher type.");

     switch(idx){
        case 0:
           blkEncStC = new CryptoBlkEncStCAes128Ctr();
           TRACE("* MAC StC Selected: hmac-sha1");
        break;
        default:
           throw CryptoException("setBlkAlgStC: MAC StC type error.");
     }
   }

   void Crypto::initMacCtS(vector<uint8_t>* initVect) noexcept(true){
      macCtS->init(initVect);
   }

   void Crypto::hmacCtS(const uint8_t* msg, int smsg, uint8_t* sign, 
                        unsigned int* ssize) const noexcept(false){
      macCtS->hmac(msg, smsg, sign, ssize);
   }

   void Crypto::initMacStC(vector<uint8_t>* initVect) noexcept(true){
     macStC->init(initVect);
   }

   void Crypto::hmacStC(const uint8_t* msg, int smsg, uint8_t* sign, 
                        unsigned int* ssize) const noexcept(false){
     macStC->hmac(msg, smsg, sign, ssize);
   }

   size_t Crypto::getBlockLenE(void) const noexcept(true){
         return blkEncCtS->getBlockLen();
   }

   size_t Crypto::getBlockLenD(void) const noexcept(true){
         return blkEncStC->getBlockLen();
   }

   void Crypto::initBlkEnc(vector<uint8_t>& key, vector<uint8_t>& iv) const noexcept(false){
      blkEncCtS->init(key, iv);
   }

   void Crypto::initBlkDec(vector<uint8_t>& key, vector<uint8_t>& iv) const noexcept(false){
      blkEncStC->init(key, iv);
   }

   void Crypto::encr(uint8_t* msg, int  msize, uint8_t* encrypt, int* esize) const noexcept(false){
      blkEncCtS->encrUpd(msg,  msize, encrypt, esize);
   }

   void Crypto::encrFin(uint8_t* encrypt, int* esize) const noexcept(false){
      blkEncCtS->encrFin(encrypt, esize);
   }

   void Crypto::decr(uint8_t* msg, int  msize, uint8_t* decrypt, int* dsize) const noexcept(false){
      blkEncStC->decrUpd(msg,  msize, decrypt, dsize);
   }

   void Crypto::decrFin(uint8_t* decrypt, int* dsize) const noexcept(false){
      blkEncStC->decrFin(decrypt, dsize);
   }

   template<class T>
   void Crypto::serverKeyHash(const T& in, std::vector<uint8_t>& out) const noexcept(false){
      vector<uint8_t>  buffIn,
                       buffHash,
                       buffHex;
      try{
         buffHash.resize(SHA256_DIGEST_LENGTH);
   
         for(auto i = in.begin(); i != in.end(); ++i){
            if(*i != '=')  buffIn.insert(buffIn.end(), static_cast<uint8_t>(*i));
            else           break;
         }
   
         static_cast<void>(SHA256(buffIn.data(), buffIn.size(), buffHash.data()));
         encodeHex(buffHash, buffHex);           
   
         for(auto i = buffHex.begin(); i != buffHex.end(); i+=2){
            out.insert(out.end(), *i);
            out.insert(out.end(), *(i+1));
            out.insert(out.end(), ':');
         }
         out[out.size() - 1] = 0;
     }catch(StringUtilsException& e){
	throw("serverKeyHash: " + e.what());
     }catch(...){
        throw CryptoException("serverKeyHash: data error.");
     }
   }

   CryptoDHG14Sha1::CryptoDHG14Sha1(void){
      sha1Len         = SHA1_DIGEST_LENGTH;
   }

   CryptoDHG14Sha1::~CryptoDHG14Sha1(void){ }

   void CryptoDHG14Sha1::dhHash(vector<uint8_t>& buff, vector<uint8_t>& hash) const noexcept(true){
      static_cast<void>(SHA1(buff.data(), buff.size(), hash.data()));
   }

   void CryptoDHG14Sha1::dhHash(vector<uint8_t>& buff, uint8_t* hash) const noexcept(true){
      static_cast<void>(SHA1(buff.data(), buff.size(), hash));
   }

   size_t CryptoDHG14Sha1::getDhHashSize(void) const noexcept(true){
      return sha1Len;
   }

   CryptoKeyRsa::CryptoKeyRsa(void) : keyFilePrefix("id_rsa"), nullKey("FFFFFFFF"), 
                                      id("rsa-ssh"), descr("RSA"){
      bnSharedKey   = BN_new();
      bnPrivKey     = BN_new();
      bnPrime       = BN_new();
      bnE           = BN_new();
      ctx           = BN_CTX_new();
      BN_CTX_init(ctx);
   }

   CryptoKeyRsa::~CryptoKeyRsa(void){
      BN_free(bnPrime);
      BN_free(bnSharedKey);
      BN_free(bnPrivKey);
      BN_free(bnE);

      BN_CTX_free(ctx);
   }

   const std::string& CryptoKeyRsa::getDhId(void) const noexcept(true){ 
      return id;
   }

   const std::string& CryptoKeyRsa::getDhDescr(void) const noexcept(true){ 
      return descr;
   }

   void CryptoKeyRsa::setDhKeys(vector<uint8_t>& genBuff, vector<uint8_t>& res) noexcept(false){
      BIGNUM* bnQ           = BN_new();
      BIGNUM* bnOne         = BN_new();
      BIGNUM* bnBase        = BN_new();
      BIGNUM* bnExp         = BN_new();

      if(BN_hex2bn(&bnPrime, RFC3526_PRIME) == 0)
         throw CryptoException("setDhKeys: Error converting prime string to bignum.");
   
      TRACE("* Prime number", reinterpret_cast<uint8_t*>(BN_bn2hex(bnPrime)), 
            static_cast<size_t>(BN_num_bytes(bnPrime)));

      TRACE("* Starting DH Init: ");

      if(BN_hex2bn(&bnBase, "2") == 0)
         throw CryptoException("setDhKeys: Error assigning base to bignum.");

      if(BN_hex2bn(&bnExp, "800") == 0)
         throw CryptoException("setDhKeys: Error assigning exponent string to bignum.");

      if(BN_hex2bn(&bnOne, "1") == 0)
         throw CryptoException("setDhKeys: Error assigning bignum const one.");

      if(BN_exp(bnQ, bnBase, bnExp, ctx) == 0)
         throw CryptoException("setDhKeys: Error calculating Q (power).");

      if(BN_sub(bnQ, bnQ, bnOne) == 0)
         throw CryptoException("setDhKeys: Error decrementing Q.");

      TRACE("* Q number: ", reinterpret_cast<const uint8_t*>(BN_bn2hex(bnQ)),
                              static_cast<size_t>(BN_num_bytes(bnQ)));

      if(BN_pseudo_rand_range(bnPrivKey, bnQ) == 0)
         throw CryptoException("setDhKeys: Error generating rnd Q.");

      if(BN_is_odd(bnPrivKey) != 1){
         TRACE("* Rnd number isn't odd: sub 1.: ");
         if(BN_sub(bnPrivKey, bnPrivKey, bnOne) != 1)
            throw CryptoException("setDhKeys: BN_sub error generating priv key.");
      }

      TRACE("* DH Rnd - number Private Key: ",
            reinterpret_cast<const uint8_t*>(BN_bn2hex(bnPrivKey)),
            static_cast<size_t>(BN_num_bytes(bnPrivKey)));

      if(BN_mod_exp(bnE, bnBase, bnPrivKey, bnPrime, ctx) == 0)
         throw CryptoException("setDhKeys: Error calculating Q (power).");

      TRACE("* DH E number: ", reinterpret_cast<const uint8_t*>(BN_bn2hex(bnE)),
            static_cast<size_t>(BN_num_bytes(bnE)));

      size_t   msgLen = static_cast<size_t>(BN_num_bytes(bnE));
      if( msgLen == 0 ) throw CryptoException("setDhKeys: Wrong E size.");

      genBuff.resize(msgLen);
      size_t lenE = static_cast<size_t>(BN_bn2bin(bnE, genBuff.data()));
      appendVectBuffer(res, genBuff);
      TRACE("* DH Request : \n ** E length in bits: " + to_string(lenE*8) +
            " Buffer Lenght: " + to_string(genBuff.size()), &res);

      BN_free(bnQ);
      BN_free(bnOne);
      BN_free(bnBase);
      BN_free(bnExp);
   }

   void CryptoKeyRsa::signMessage(std::string& privKey, std::vector<uint8_t>& msg,
                                  std::vector<uint8_t>& sign) const noexcept(false){
      EVP_PKEY*     vkey       = EVP_PKEY_new();
      EVP_MD_CTX*   mctx       = EVP_MD_CTX_create();
      const EVP_MD* md         = EVP_get_digestbyname("SHA1");

      #ifdef __clang__
      #pragma clang diagnostic push
      #pragma clang diagnostic ignored "-Wold-style-cast"
      #endif

      if(EVP_DigestInit_ex(mctx, md, nullptr) != 1)
         throw CryptoException(string("signMessage: EVP_PKEY_assign_RSA (1) failed: ") +
                               ERR_error_string(ERR_get_error(), nullptr));
      #ifdef __clang__
      #pragma clang diagnostic pop
      #endif

      TRACE("* Msg To Sign: ", &msg);

      vector<uint8_t> b64PrivKey;
  
      loadFileMem(privKey, b64PrivKey, false);
  
      TRACE("* Auth Private Key: " + privKey, &b64PrivKey);
  
      BIO* bioPrivKey = BIO_new_mem_buf(b64PrivKey.data(), safeInt(b64PrivKey.size()));
      RSA* rsaPrivKey = RSA_new();
  
      if(PEM_read_bio_RSAPrivateKey(bioPrivKey, &rsaPrivKey, nullptr, nullptr) == nullptr)
         throw(CryptoException(string("signMessage: Error loading private key in BIO object.") +
               ERR_error_string(ERR_get_error(), nullptr)));
  
      sign.resize(safeSizeT(RSA_size(rsaPrivKey)));
  
      #ifdef __clang__
      #pragma clang diagnostic push
      #pragma clang diagnostic ignored "-Wold-style-cast"
      #endif

      if(EVP_PKEY_assign_RSA(vkey, rsaPrivKey) != 1)
         throw CryptoException(string("signMessage: EVP_PKEY_assign_RSA (2) failed: ") +
                               ERR_error_string(ERR_get_error(), nullptr));
      #ifdef __clang__
      #pragma clang diagnostic pop
      #endif

      if(EVP_DigestSignInit(mctx, nullptr, md, nullptr, vkey) != 1)
         throw CryptoException(string("signMessage: EVP_DigestSignInit failed: ") +
                               ERR_error_string(ERR_get_error(), nullptr));

      if(EVP_DigestSignUpdate(mctx, msg.data(), msg.size()) != 1)
         throw CryptoException(string("signMessage: EVP_DigestSignUpdate failed: ") +
                               ERR_error_string(ERR_get_error(), nullptr));
      size_t signlen = sign.size();
      if(EVP_DigestSignFinal(mctx, sign.data(), &signlen) != 1)
         throw CryptoException(string("signMessage: EVP_DigestVerifyFinal failed: ") +
                               ERR_error_string(ERR_get_error(), nullptr));
      TRACE("* Auth Msg Sign: ", &sign);

      secureZeroing(b64PrivKey.data(), b64PrivKey.size());

      BIO_vfree(bioPrivKey);
      EVP_MD_CTX_destroy(mctx);
      EVP_PKEY_free(vkey);
   }

   void CryptoKeyRsa::signDH(vector<uint8_t>& buff, vector<uint8_t>& sign,
                               BIGNUM* mod, BIGNUM* exp) const noexcept(false){
      RSA       *serverPublicKey  = RSA_new();

      serverPublicKey->n          = mod;
      serverPublicKey->e          = exp;

      TRACE("* Signature - N: ", reinterpret_cast<uint8_t*>(BN_bn2hex(mod)), 
            static_cast<size_t>(BN_num_bytes(mod)));

      size_t rsasize =  safeSizeT(RSA_size(serverPublicKey));
      TRACE("* Signature - Server Pubkey Length in bits: " + to_string(rsasize * BYTE_LENGHT) );

      EVP_PKEY  *vkey             = EVP_PKEY_new();
      EVP_MD_CTX* mctx            = EVP_MD_CTX_create();
      const EVP_MD* md            = EVP_get_digestbyname("SHA1");
      if(EVP_DigestInit_ex(mctx, md, nullptr) != 1)
         throw CryptoException(string("signDH: EVP_PKEY_assign_RSA (1) failed: ") +
                                          ERR_error_string(ERR_get_error(), nullptr));
      #ifdef __clang__
      #pragma clang diagnostic push
      #pragma clang diagnostic ignored "-Wold-style-cast"
      #endif

      if(EVP_PKEY_assign_RSA(vkey, RSAPublicKey_dup(serverPublicKey)) != 1)
         throw CryptoException(string("signDH: EVP_PKEY_assign_RSA (2) failed: ") +
                               ERR_error_string(ERR_get_error(), nullptr));
      #ifdef __clang__
      #pragma clang diagnostic pop
      #endif

      TRACE("* Signature - Buffer: ",  &buff);
      TRACE("* Signature - Signature: ",  &sign);
      if(EVP_DigestVerifyInit(mctx, nullptr, md, nullptr, vkey) != 1)
         throw CryptoException(string("signDH: EVP_DigestVerifyInit failed: ") +
                                      ERR_error_string(ERR_get_error(), nullptr));

      if(EVP_DigestVerifyUpdate(mctx, buff.data(), buff.size()) != 1)
         throw CryptoException(string("signDH: EVP_DigestVerifyUpdate failed: ") +
                                      ERR_error_string(ERR_get_error(), nullptr));

      if(EVP_DigestVerifyFinal(mctx, sign.data(), sign.size()) != 1)
         throw CryptoException(string("signDH: EVP_DigestVerifyFinal failed: ") +
                                      ERR_error_string(ERR_get_error(), nullptr));
      EVP_MD_CTX_destroy(mctx);
      EVP_PKEY_free(vkey);

      OPENSSL_free(serverPublicKey);
   }
   
   void CryptoKeyRsa::setDhSharedKey(BIGNUM* f) noexcept(false){
      if(BN_mod_exp(bnSharedKey, f, bnPrivKey, bnPrime, ctx) == 0)
         throw CryptoException("setDhSharedKey: Error calculating Shared Key.");

      TRACE("* DH Reply Parsing End. \n ** Shared Key: ", reinterpret_cast<uint8_t*>(BN_bn2hex(bnSharedKey)),
            static_cast<size_t>(BN_num_bytes(bnSharedKey)));
      TRACE(" ** F: ", reinterpret_cast<uint8_t*>(BN_bn2hex(f)),
            static_cast<size_t>(BN_num_bytes(f)));
   }

   BIGNUM* CryptoKeyRsa::getE(void) const noexcept(true){
      return bnE;
   }

   BIGNUM* CryptoKeyRsa::getSharedKey(void) const noexcept(true){
      return bnSharedKey;
   }

   const string& CryptoKeyRsa::getKeyFilePrefix(void) const noexcept(true){
      return keyFilePrefix;
   }

   const string& CryptoKeyRsa::getNullKey(void) const noexcept(true){
      return nullKey;
   }

   CryptoMacCtS::~CryptoMacCtS(void){}

   CryptoMacStC::~CryptoMacStC(void){}

   void CryptoMacCtSSha1::hmac(const uint8_t* msg, int smsg, 
                               uint8_t* sign, unsigned int* ssize) const noexcept(false) {
      if(HMAC(EVP_sha1(), static_cast<const uint8_t*>(iv->data()), 
              safeInt(iv->size()), msg, safeSizeT(smsg), sign, ssize) == 0)
                         throw CryptoException("hmac: Error Calculating HMAC on output.");
   }

   void CryptoMacCtSSha1::init(vector<uint8_t>* initVect) noexcept(true) {
      iv = initVect;
   }

   void CryptoMacStCSha1::hmac(const uint8_t* msg, int smsg, 
                               uint8_t* sign, unsigned int* ssize) const noexcept(false) {
      if(HMAC(EVP_sha1(), static_cast<const uint8_t*>(iv->data()), 
              safeInt(iv->size()), msg, safeSizeT(smsg), sign, ssize) == 0)
                         throw CryptoException("hmac: Error Calculating HMAC on output.");
   }

   void CryptoMacStCSha1::init(vector<uint8_t>* initVect) noexcept(true) {
      iv = initVect;
   }

   CryptoBlkEncCtSAes128Ctr::CryptoBlkEncCtSAes128Ctr(void){
      ectxE                 = EVP_CIPHER_CTX_new(); 
      if(ectxE == nullptr)  throw CryptoException("Error Initializing ectxE."); 
   }

   CryptoBlkEncCtSAes128Ctr::~CryptoBlkEncCtSAes128Ctr(void){
      EVP_CIPHER_CTX_free(ectxE); 
   }

   void CryptoBlkEncCtSAes128Ctr::init(vector<uint8_t>& key, vector<uint8_t>& iv) noexcept(false){
      if( EVP_EncryptInit_ex(ectxE, EVP_aes_128_ctr(), nullptr, key.data(), iv.data()) != 1)
         throw CryptoException("init: Error Configuring Encrypting AES block");
   }

   void CryptoBlkEncCtSAes128Ctr::encrUpd(uint8_t* msg, int  msize,
                                          uint8_t* encrypt, int* esize) const noexcept(false){
      if(EVP_EncryptUpdate(ectxE, encrypt, esize, msg, msize) != 1)
         throw CryptoException("encrUpd: Error Encrypting Payload");
   }

   void CryptoBlkEncCtSAes128Ctr::encrFin(uint8_t* encrypt, int* esize) const noexcept(false){
      if(EVP_EncryptFinal_ex(ectxE, encrypt, esize) != 1)
         throw CryptoException("encrFin: Error Encrypting Payload - Final");
   }

   size_t CryptoBlkEncCtSAes128Ctr::getBlockLen(void) const noexcept(true){
      return AES_BLOCK_LEN;  
   }

   CryptoBlkEncStCAes128Ctr::CryptoBlkEncStCAes128Ctr(void){
      ectxD                 = EVP_CIPHER_CTX_new(); 
      if(ectxD == nullptr)  throw CryptoException("Error Initializing ectxD.");
   }

   CryptoBlkEncStCAes128Ctr::~CryptoBlkEncStCAes128Ctr(void){
      EVP_CIPHER_CTX_free(ectxD);
   }

   void CryptoBlkEncStCAes128Ctr::init(vector<uint8_t>& key, vector<uint8_t>& iv) noexcept(false){
      if( EVP_DecryptInit_ex(ectxD, EVP_aes_128_ctr(), nullptr, key.data(), iv.data()) != 1)
         throw CryptoException("init: Error Configuring Decrypting AES block");
   }
   void CryptoBlkEncStCAes128Ctr::decrUpd(uint8_t* msg, int  msize,
                                          uint8_t* decrypt, int* dsize) const noexcept(false){
      if(EVP_DecryptUpdate(ectxD, decrypt, dsize, msg, msize) != 1)
         throw CryptoException("decrUpd: Error Decrypting Payload");
   }

   void CryptoBlkEncStCAes128Ctr::decrFin(uint8_t* decrypt, int* dsize) const noexcept(false){
      if(EVP_DecryptFinal_ex(ectxD, decrypt,  dsize) != 1)
         throw CryptoException("decrFin: Error Decrypting Payload - Final");
   }

   size_t CryptoBlkEncStCAes128Ctr::getBlockLen(void) const noexcept(true){
      return AES_BLOCK_LEN;  
   }

   #if defined  __clang_major__ && !defined __APPLE__ && __clang_major__ >= 4
   #pragma clang diagnostic pop
   #endif

}
