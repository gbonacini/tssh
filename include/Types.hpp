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

#ifndef  TYPES_UTILS
#define  TYPES_UTILS

#include <limits>
#include <cstddef>
#include <string>

#include <sys/types.h>
#include <stdint.h> 

namespace typeutils{

   class  TypesUtilsException final {
           public:
                   explicit    TypesUtilsException(int errNum);
                   explicit    TypesUtilsException(std::string errString);
                               TypesUtilsException(int errNum, std::string errString);
                   std::string what(void)                                                     const noexcept(true);
              private:
                   std::string errorMessage;
                   int errorCode;
   };

   #ifdef __clang__
   #pragma clang diagnostic push
   #pragma clang diagnostic ignored "-Wsign-compare"
   #endif

   template<class T>
   ssize_t safeSsizeT(T size)  noexcept(false){     
      if(size > std::numeric_limits<ssize_t>::max())
         throw TypesUtilsException("Invalid conversion to ssize_t: overflow.");
      return static_cast<ssize_t>(size);
   }

   template<class T>
   int safeInt(T size)  noexcept(false){        
      if(size > std::numeric_limits<int>::max())
         throw TypesUtilsException("Invalid conversion to int: overflow.");
      return static_cast<int>(size);
   }

   template<class T>
   ptrdiff_t safePtrdiff(T offset)  noexcept(false){  
      if(offset > std::numeric_limits<ptrdiff_t>::max())
         throw TypesUtilsException("Invalid conversion to ptrdiff_t: overflow.");
      return static_cast<ptrdiff_t>(offset);
   }

   template<class T>
   size_t safeSizeT(T size)  noexcept(false){
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to size_t: negative value.");
      if(size > std::numeric_limits<size_t>::max())
         throw TypesUtilsException("Invalid conversion to size_t: overflow.");
      return static_cast<size_t>(size);
   }

   template<class T>
   unsigned int safeUInt(T size)  noexcept(false){       
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to unsigned int: negative value.");
      if(size > std::numeric_limits<unsigned int>::max())
         throw TypesUtilsException("Invalid conversion to unsigned int: overflow.");
      return static_cast<unsigned int>(size);
   }

   template<class T>
   unsigned long safeULong(T size)  noexcept(false){      
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to unsigned long: negative value.");
      if(size > std::numeric_limits<unsigned long>::max())
         throw TypesUtilsException("Invalid conversion to unsigned long: overflow.");
      return static_cast<unsigned long>(size);
   }

   template<class T>
   uint32_t safeUint32(T size)  noexcept(false){     
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to uint32_t: negative value.");
      if(size > std::numeric_limits<uint32_t>::max())
         throw TypesUtilsException("Invalid conversion to uint32_t: overflow.");
      return static_cast<uint32_t>(size);
   }

   #ifdef __clang__
   #pragma clang diagnostic pop
   #endif

   extern template ptrdiff_t       safePtrdiff<size_t>(size_t)                noexcept(false);
   extern template ssize_t         safeSsizeT<size_t>(size_t)                 noexcept(false);
   extern template int             safeInt<unsigned int>(unsigned int)        noexcept(false);
   extern template int             safeInt<size_t>(size_t)                    noexcept(false);
   extern template size_t          safeSizeT<ssize_t>(ssize_t)                noexcept(false);
   extern template size_t          safeSizeT<int>(int)                        noexcept(false);
   extern template size_t          safeSizeT<uint32_t>(uint32_t)              noexcept(false);
   extern template size_t          safeSizeT<long long int>(long long int)    noexcept(false);
   extern template uint32_t        safeUint32<int>(int)                       noexcept(false);
   extern template uint32_t        safeUint32<unsigned long>(unsigned long)   noexcept(false);
   extern template unsigned int    safeUInt<size_t>(size_t)                   noexcept(false);
   extern template unsigned long   safeULong<int>(int)                        noexcept(false);
   extern template unsigned long   safeULong<long int>(long int)              noexcept(false);
}
#endif
