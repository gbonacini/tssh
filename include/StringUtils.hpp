// -----------------------------------------------------------------
// Tssh - A ssh test client. 
// Copyright (C) 2016-2023  Gabriele Bonacini
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

#pragma once

#include <sys/types.h>
#include <termios.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wold-style-cast"
#endif

#include <openssl/bn.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#include <exception>
#include <vector>
#include <set>
#include <string>

#include <anyexcept.hpp>
#include <Types.hpp>

#ifndef NOTRACE
#define TRACE(...)  if(stringutils::getDebug()) trace(__VA_ARGS__) 
#else
#define TRACE(...)  
#endif

namespace stringutils{

   class  StringUtilsException final : public std::exception {
           public:
                   explicit    StringUtilsException(int errNum);
                   explicit    StringUtilsException(std::string&  errString);
                   explicit    StringUtilsException(std::string&& errString);
                               StringUtilsException(int errNum, std::string errString);
                   const char* what(void)                                                     const noexcept override;
                   int         getErrorCode(void)                                             const noexcept;
              private:
                   std::string errorMessage;
                   int errorCode;
   };

   void      setDebug(bool onOff)                                                                   noexcept;
   bool      getDebug(void)                                                                         noexcept;
   uint32_t  charToUint32(const uint8_t* tmp)                                                       anyexcept;
   void      uint32ToUChars(uint8_t* dest, uint32_t number)                                         noexcept;
   void      uint32ToUChars(std::vector<uint8_t>& dest, uint32_t number)                            anyexcept;
   void      appendStringAsUint32t(const std::string& orig,
                                   std::vector<uint8_t>& dest, size_t offset)                       anyexcept;
   void      appendVectBuffer(std::vector<uint8_t>& buffer, 
                              const char* orig, size_t len, size_t start, 
                             size_t stop)                                                           anyexcept;
   void      appendVectBuffer(std::vector<uint8_t>& buffer,
                              const uint8_t* orig, size_t len, 
                              size_t start, size_t stop)                                            anyexcept;
   void      appendVectBuffer(std::vector<uint8_t>& buffer,
                              const std::vector<uint8_t>& orig)                                     anyexcept;
   void      appendVectBuffer(std::vector<uint8_t>& buffer, 
                              const std::vector<uint8_t>& orig, 
                              size_t start, size_t removePad)                                       anyexcept;
   void      trace(std::string header)                                                              noexcept;
   void      trace(std::string header, const std::vector<uint8_t>* buff,
                   size_t begin = 0, size_t end = 0, size_t max = 0 )                               noexcept;
   void      trace(const  char*  header, const uint8_t* buff, const size_t size = 0,
                   size_t begin = 0, size_t end = 0 )                                               noexcept;
   void      addVarLengthDataString(const auto& item, std::vector<uint8_t>& target)                 anyexcept;
   void      addVarLengthDataCCharStr(const char* item, std::vector<uint8_t>& target)               anyexcept;
   size_t    insVarLengthDataString(const std::string item, size_t start,
                                    std::vector<uint8_t>& target)                                   anyexcept;
   size_t    getVariableLengthRawValue(const std::vector<uint8_t>& index, 
                                       size_t offset, auto& destination)                            anyexcept;

   size_t    getVariableLengthRawValue(const std::vector<uint8_t>& index, 
                                       size_t offset,
                                       std::vector<uint8_t> destination[],
                                       int item)                                                    anyexcept;
   size_t    getVariableLengthValueCsv(std::vector<uint8_t>& index,
                                       std::vector<char>& buff,
                                       std::vector<std::string>* algorithmStrings,
                                       int item, size_t offset)                                     anyexcept;
   size_t    getVariableLengthValueCsv(std::vector<uint8_t>& index, 
                                       std::vector<char>& buff,
                                       std::set<std::string>* algorithmStrings, 
                                       int item, size_t offset)                                     anyexcept;
   size_t    getVariableLengthSingleBignum(const std::vector<uint8_t>& index, 
                                           size_t offset,
                                           BIGNUM* keyAndSign)                                      anyexcept;
   void      insArrayVals(const auto& orig, size_t origOffset,
                          std::vector<uint8_t>& dest, size_t destOffset)                            anyexcept;
   void      decodeB64(const auto& in, auto& out)                                                   anyexcept;
   void      encodeB64(const auto& in, auto& out)                                                   anyexcept;
   void      encodeHex(const std::vector<uint8_t>& in, std::vector<uint8_t>& out)                   anyexcept;
   void      getPassword(std::vector<uint8_t>& pwd)                                                 anyexcept;
   void      getPassword(std::vector<uint8_t>& pwd, struct termios* oldTerm, 
                         struct termios* newTerm)                                                   anyexcept;
   void*     secureZeroing(void *orig, size_t len)                                                  noexcept;
   void      loadFileMem(std::string fileName, auto& dest, bool terminator)                         anyexcept;

   extern template
   void   encodeB64(const std::vector<uint8_t>& in, std::string& out)                               anyexcept;
   extern template
   void   decodeB64(const std::string& in, std::vector<uint8_t>& out)                               anyexcept;
   extern template 
   void   insArrayVals(const std::vector<uint8_t>& orig, size_t origOffset,
                       std::vector<uint8_t>& dest, size_t destOffset)                               anyexcept;
   extern template 
   void   addVarLengthDataString(const std::string& item,
                                 std::vector<uint8_t>& target)                                      anyexcept;
   extern template 
   void   addVarLengthDataString(const std::vector<uint8_t>&item,
                                 std::vector<uint8_t>& target)                                      anyexcept;
   extern template 
   size_t getVariableLengthRawValue(const std::vector<uint8_t>& index,
                                    size_t offset, std::string& destination)                        anyexcept;
   extern template
   size_t getVariableLengthRawValue(const std::vector<uint8_t>& index,
                                    size_t offset, std::vector<uint8_t>&destination)                anyexcept;
   extern template 
   void   loadFileMem(std::string fileName, std::vector<uint8_t>& dest,
                      bool terminator)                                                              anyexcept;

 }
   
