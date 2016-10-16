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

#include <Types.cpp>

namespace typeutils{

  template ptrdiff_t       safePtrdiff(size_t size);
  template ssize_t         safeSsizeT(size_t size);
  template int             safeInt(unsigned int size);
  template int             safeInt(size_t size);
  template size_t          safeSizeT(ssize_t size);
  template size_t          safeSizeT(int size);
  template size_t          safeSizeT(uint32_t size);
  template size_t          safeSizeT(long long int size);
  template uint32_t        safeUint32(int size);
  template uint32_t        safeUint32(unsigned long size);
  template unsigned int    safeUInt(size_t size);
  template unsigned long   safeULong(int size);
  template unsigned long   safeULong(long int size);
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
#pragma clang diagnostic pop
#endif
