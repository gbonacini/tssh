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

#include <StringUtils.hpp>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif

#if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wundefined-func-template"
#endif

#include <StringUtils.cpp>

namespace stringutils{
   template void   encodeB64(const std::vector<uint8_t>& in, std::string& out)                    noexcept(false);
   template void   decodeB64(const std::string& in, std::vector<uint8_t>& out)                    noexcept(false);
   template void   insArrayVals(const std::vector<uint8_t>& orig, size_t origOffset, 
                                std::vector<uint8_t>& dest, size_t destOffset)                    noexcept(false);
   template void   addVarLengthDataString(const std::string& item,
                                          std::vector<uint8_t>& target)                           noexcept(false);
   template void   addVarLengthDataString(const std::vector<uint8_t>&item,
                                          std::vector<uint8_t>& target)                           noexcept(false); 
   template size_t getVariableLengthRawValue(const std::vector<uint8_t>& index,
                                             size_t offset, std::string& destination)             noexcept(false);
   template size_t getVariableLengthRawValue(const std::vector<uint8_t>& index,
                                             size_t offset, std::vector<uint8_t>&destination)     noexcept(false);
   template void   loadFileMem(std::string fileName, std::vector<uint8_t>& dest, 
                               bool terminator)                                                   noexcept(false);
}

#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
#pragma clang diagnostic pop
#endif
