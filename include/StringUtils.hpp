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

#ifndef STRING_UTILS
#define STRING_UTILS

#include <iostream>
#include <iomanip>
#include <vector>
#include <set>
#include <string>
#include <cstring>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>

#include <arpa/inet.h>

#include <openssl/bn.h>

#include <Types.hpp>

#ifndef NOTRACE
#define TRACE(...)  if(stringutils::getDebug()) trace(__VA_ARGS__) 
#else
#define TRACE(...)  
#endif

namespace stringutils{

   class  StringUtilsException final {
           public:
                   explicit    StringUtilsException(int errNum);
                   explicit    StringUtilsException(std::string&  errString);
                   explicit    StringUtilsException(std::string&& errString);
                               StringUtilsException(int errNum, std::string errString);
                   std::string what(void)                                                     const noexcept(true);
              private:
                   std::string errorMessage;
                   int errorCode;
   };

   void      setDebug(bool onOff)                                                                   noexcept(true);
   bool      getDebug(void)                                                                         noexcept(true);
   uint32_t  charToUint32(const uint8_t* tmp)                                                       noexcept(false);
   void      uint32ToUChars(uint8_t* dest, uint32_t number)                                         noexcept(true);
   void      uint32ToUChars(std::vector<uint8_t>& dest, uint32_t number)                            noexcept(false);
   void      appendStringAsUint32t(const std::string& orig,
                                   std::vector<uint8_t>& dest, size_t offset)                       noexcept(false);
   void      appendVectBuffer(std::vector<uint8_t>& buffer, 
                              const char* orig, size_t len, size_t start, 
                             size_t stop)                                                           noexcept(false);
   void      appendVectBuffer(std::vector<uint8_t>& buffer,
                              const uint8_t* orig, size_t len, 
                              size_t start, size_t stop)                                            noexcept(false);
   void      appendVectBuffer(std::vector<uint8_t>& buffer,
                              const std::vector<uint8_t>& orig)                                     noexcept(false);
   void      appendVectBuffer(std::vector<uint8_t>& buffer, 
                              const std::vector<uint8_t>& orig, 
                              size_t start, size_t removePad)                                       noexcept(false);
   void      trace(std::string header)                                                              noexcept(true);
   void      trace(std::string header, const std::vector<uint8_t>* buff,
                   size_t begin = 0, size_t end = 0, size_t max = 0 )                               noexcept(true);
   void      trace(const  char*  header, const uint8_t* buff, const size_t size = 0,
                   size_t begin = 0, size_t end = 0 )                                               noexcept(true);
   template<class T>
   void      addVarLengthDataString(const T& item, std::vector<uint8_t>& target)                    noexcept(false);
   void      addVarLengthDataCCharStr(const char* item, std::vector<uint8_t>& target)               noexcept(false);
   size_t    insVarLengthDataString(const std::string item, size_t start,
                                    std::vector<uint8_t>& target)                                   noexcept(false);
   template<class T>
   size_t    getVariableLengthRawValue(const std::vector<uint8_t>& index, 
                                       size_t offset, T& destination)                               noexcept(false);

   size_t    getVariableLengthRawValue(const std::vector<uint8_t>& index, 
                                       size_t offset,
                                       std::vector<uint8_t> destination[],
                                       int item)                                                    noexcept(false);
   size_t    getVariableLengthValueCsv(std::vector<uint8_t>& index,
                                       std::vector<char>& buff,
                                       std::vector<std::string>* algorithmStrings,
                                       int item, size_t offset)                                     noexcept(false);
   size_t    getVariableLengthValueCsv(std::vector<uint8_t>& index, 
                                       std::vector<char>& buff,
                                       std::set<std::string>* algorithmStrings, 
                                       int item, size_t offset)                                     noexcept(false);
   size_t    getVariableLengthSingleBignum(const std::vector<uint8_t>& index, 
                                           size_t offset,
                                           BIGNUM* keyAndSign)                                      noexcept(false);
   template<class T>
   void      insArrayVals(const T& orig, size_t origOffset,
                          std::vector<uint8_t>& dest, size_t destOffset)                            noexcept(false);
   template<class T, class T2>
   void      decodeB64(const T& in, T2& out)                                                        noexcept(false);
   template<class T, class T2>
   void      encodeB64(const T& in, T2& out)                                                        noexcept(false);
   void      encodeHex(const std::vector<uint8_t>& in, std::vector<uint8_t>& out)                   noexcept(false);
   void      getPassword(std::vector<uint8_t>& pwd)                                                 noexcept(false);
   void      getPassword(std::vector<uint8_t>& pwd, struct termios* oldTerm, 
                         struct termios* newTerm)                                                   noexcept(false);
   void*     secureZeroing(void *orig, size_t len)                                                  noexcept(true);
   template<class T>
   void      loadFileMem(std::string fileName, T& dest, bool terminator)                            noexcept(false);

   extern template
   void   encodeB64(const std::vector<uint8_t>& in, std::string& out)                               noexcept(false);
   extern template
   void   decodeB64(const std::string& in, std::vector<uint8_t>& out)                               noexcept(false);
   extern template 
   void   insArrayVals(const std::vector<uint8_t>& orig, size_t origOffset,
                       std::vector<uint8_t>& dest, size_t destOffset)                               noexcept(false);
   extern template 
   void   addVarLengthDataString(const std::string& item,
                                 std::vector<uint8_t>& target)                                      noexcept(false);
   extern template 
   void   addVarLengthDataString(const std::vector<uint8_t>&item,
                                 std::vector<uint8_t>& target)                                      noexcept(false);
   extern template 
   size_t getVariableLengthRawValue(const std::vector<uint8_t>& index,
                                    size_t offset, std::string& destination)                        noexcept(false);
   extern template
   size_t getVariableLengthRawValue(const std::vector<uint8_t>& index,
                                    size_t offset, std::vector<uint8_t>&destination)                noexcept(false);
   extern template 
   void   loadFileMem(std::string fileName, std::vector<uint8_t>& dest,
                      bool terminator)                                                              noexcept(false);

 }
   
#endif
