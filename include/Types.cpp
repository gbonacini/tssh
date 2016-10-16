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

namespace typeutils{
 
   using std::string;
   using std::numeric_limits;

   TypesUtilsException::TypesUtilsException(int errNum){
           errorCode=errNum;
           errorMessage="None";
   }   
   
   TypesUtilsException::TypesUtilsException(string errString){
           errorMessage=errString;
           errorCode=0;
   }   
   
   TypesUtilsException::TypesUtilsException(int errNum, string errString){
           errorMessage=errString;
           errorCode=errNum;
   }   
   
   string TypesUtilsException::what() const noexcept(true){
           return errorMessage;
   }   
 
   template<class T>
   ssize_t safeSsizeT(T size)  noexcept(false){     
      if(size > numeric_limits<ssize_t>::max())
         throw TypesUtilsException("Invalid conversion to ssize_t: overflow.");
      return static_cast<ssize_t>(size);
   }

   template<class T>
   int safeInt(T size)  noexcept(false){        
      if(size > numeric_limits<int>::max())
         throw TypesUtilsException("Invalid conversion to int: overflow.");
      return static_cast<int>(size);
   }

   template<class T>
   ptrdiff_t safePtrdiff(T offset)  noexcept(false){  
      if(offset > numeric_limits<ptrdiff_t>::max())
         throw TypesUtilsException("Invalid conversion to ptrdiff_t: overflow.");
      return static_cast<ptrdiff_t>(offset);
   }

   template<class T>
   size_t safeSizeT(T size)  noexcept(false){
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to size_t: negative value.");
      if(size > numeric_limits<size_t>::max())
         throw TypesUtilsException("Invalid conversion to size_t: overflow.");
      return static_cast<size_t>(size);
   }

   template<class T>
   unsigned int safeUInt(T size)  noexcept(false){       
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to unsigned int: negative value.");
      if(size > numeric_limits<unsigned int>::max())
         throw TypesUtilsException("Invalid conversion to unsigned int: overflow.");
      return static_cast<unsigned int>(size);
   }

   template<class T>
   unsigned long safeULong(T size)  noexcept(false){      
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to unsigned long: negative value.");
      if(size > numeric_limits<unsigned long>::max())
         throw TypesUtilsException("Invalid conversion to unsigned long: overflow.");
      return static_cast<unsigned long>(size);
   }

   template<class T>
   uint32_t safeUint32(T size)  noexcept(false){     
      if(size < 0)       
         throw TypesUtilsException("Invalid conversion to uint32_t: negative value.");
      if(size > numeric_limits<uint32_t>::max())
         throw TypesUtilsException("Invalid conversion to uint32_t: overflow.");
      return static_cast<uint32_t>(size);
   }

}
