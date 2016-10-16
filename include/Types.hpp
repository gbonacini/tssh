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
                   TypesUtilsException(int errNum);
                   TypesUtilsException(std::string errString);
                   TypesUtilsException(int errNum, std::string errString);
                   std::string what(void)                                                     const noexcept(true);
              private:
                   std::string errorMessage;
                   int errorCode;
   };

   template<class T>
   ssize_t            safeSsizeT(T size)          noexcept(false);

   template<class T>
   size_t             safeSizeT(T size)           noexcept(false);

   template<class T>
   int                safeInt(T size)             noexcept(false);

   template<class T>
   unsigned int       safeUInt(T size)            noexcept(false);

   template<class T>
   unsigned long      safeULong(T size)           noexcept(false);

   template<class T>
   uint32_t           safeUint32(T size)          noexcept(false);

   template<class T>
   ptrdiff_t          safePtrdiff(T offset)       noexcept(false);

}
#endif
