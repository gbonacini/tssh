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

#include <type_traits>

namespace conceptsLib{

template<typename V>
concept is_appendable = requires (V v ){
     v.clear();
     v.end();
};

template<typename V>
concept is_constantIterable = requires (V v ){
     v.cbegin();
     v.cend();
};

template<typename V>
concept is_iterable = requires (V v ){
     v.begin();
     v.end();
};

template<typename V>
concept is_rawdata_accessible = requires (V v ){
     v.data();
};

template<typename V>
concept is_integral = requires (V ){
     std::is_integral_v<V>;
};

} //End namespace
