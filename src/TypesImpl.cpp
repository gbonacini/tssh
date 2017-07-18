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

#include <Types.hpp>

#ifdef __GNUC__  
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif

#if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundefined-func-template"
#endif

namespace typeutils{

  TypesUtilsException::TypesUtilsException(int errNum) : 
                       errorMessage("None"), errorCode(errNum){}   
  
  TypesUtilsException::TypesUtilsException(std::string errString) : 
                       errorMessage(errString), errorCode(0){}   
  
  TypesUtilsException::TypesUtilsException(int errNum, std::string errString) : 
                       errorMessage(errString), errorCode(errNum) {}   
  
  std::string TypesUtilsException::what() const noexcept(true){
          return errorMessage;
  }   

  template ptrdiff_t       safePtrdiff(size_t size)            noexcept(false);
  template ssize_t         safeSsizeT(size_t size)             noexcept(false);
  template int             safeInt(unsigned int size)          noexcept(false);
  template int             safeInt(size_t size)                noexcept(false);
  template size_t          safeSizeT(ssize_t size)             noexcept(false);
  template size_t          safeSizeT(int size)                 noexcept(false);
  template size_t          safeSizeT(uint32_t size)            noexcept(false);
  template size_t          safeSizeT(long long int size)       noexcept(false);
  template uint32_t        safeUint32(int size)                noexcept(false);
  template uint32_t        safeUint32(unsigned long size)      noexcept(false);
  template unsigned int    safeUInt(size_t size)               noexcept(false);
  template unsigned long   safeULong(int size)                 noexcept(false);
  template unsigned long   safeULong(long int size)            noexcept(false);
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
#pragma clang diagnostic pop
#endif
