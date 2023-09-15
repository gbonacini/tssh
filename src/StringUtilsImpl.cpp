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

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <cstring>

#include <iostream>
#include <iomanip>

#include <StringUtils.hpp>

namespace stringutils{

  using std::cerr,
        std::dec,
        std::hex,
        std::setfill,
        std::setw,
        std::string,
        std::to_string,
        std::vector,
        std::set,
        typeutils::safePtrdiff,
        typeutils::safeUint32,
        typeutils::safeInt,
        typeutils::safeSizeT,
        conceptsLib::is_rawdata_accessible,
        conceptsLib::is_iterable,
        conceptsLib::is_constantIterable;

  static bool             debug         { false };

  static const  char      convTable[]   {
                                 'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
                                 'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
                                 'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
                                 'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
  };

  static const  uint8_t   checkTable[]  {
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255,   63,
                                  52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255, 255, 255, 255, 255,
                                 255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
                                  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
                                 255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
                                  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255
   };

   StringUtilsException::StringUtilsException(int errNum)
        :   errorMessage{"None"}, errorCode{errNum}
   {}
   
   StringUtilsException::StringUtilsException(string& errString)
        :  errorMessage{errString}, errorCode{0}
   {}
   
   StringUtilsException::StringUtilsException(string&& errString)
        :  errorMessage{std::move(errString)}, errorCode{0}
   {}
   
   StringUtilsException::StringUtilsException(int errNum, string errString)
        :  errorMessage{errString}, errorCode{errNum}
   {}
   
   const char* StringUtilsException::what() const noexcept{
      return errorMessage.c_str();
   }

   int  StringUtilsException::getErrorCode(void)  const noexcept{
      return errorCode;
   }
 
   void setDebug(bool onOff) noexcept{
      debug = onOff;
   }
 
   bool getDebug(void) noexcept{
      return debug;
   }
  
  uint32_t charToUint32(const uint8_t* tmp) anyexcept{
     if(tmp == nullptr)
        throw StringUtilsException("charToUint32: invalid pointer.");
     uint32_t result;
     uint8_t* handler { reinterpret_cast<uint8_t*>(&result) };
     static_cast<void>(memcpy(handler, tmp, sizeof(uint32_t)));
     return ntohl(result);
  }
  
  void uint32ToUChars(uint8_t* dest, uint32_t number) noexcept{
     uint32_t tmp     { htonl(number) };
     uint8_t* handler { reinterpret_cast<uint8_t*>(&tmp) };
     static_cast<void>(memcpy(dest, handler, sizeof(uint32_t)));
  }
  
  void uint32ToUChars(vector<uint8_t>& dest, uint32_t number) anyexcept{
     uint32_t tmp     { htonl(number) };
     uint8_t* handler { reinterpret_cast<uint8_t*>(&tmp) };
     try{
        dest.insert(dest.end(), handler, handler + sizeof(uint32_t));
     }catch(...){
    throw StringUtilsException("uint32ToUChars: Data error.");
     }
  }
  
  void appendStringAsUint32t(const string& orig, vector<uint8_t>& dest, 
                                          size_t offset) anyexcept{
     if(orig.size() < offset)
        throw StringUtilsException("appendStringAsUint32t: Invalid offset.");

     try{
        for(auto i{orig.cbegin()+safePtrdiff(offset)}; i!=orig.cend(); ++i){
           uint32_t tmp     { htonl(static_cast<uint32_t>(*i)) };
           uint8_t* handler { reinterpret_cast<uint8_t*>(&tmp) };
           dest.insert(dest.end(), handler, handler+sizeof(uint32_t));
        }
     }catch(...){
        throw StringUtilsException("appendStringAsUint32t: translation error.");
     }
  }
  
  void appendVectBuffer(vector<uint8_t>& buffer, const char* orig, 
                        size_t len, size_t start, size_t stop) anyexcept{

     if(start > len-1 || stop > len-1 || len==0)
        throw StringUtilsException("appendVectBuffer : a : Invalid index merging vect and buffer.");
  
     uint32ToUChars(buffer, safeUint32(len));

     try{ 
        buffer.insert(buffer.end(), orig, orig+stop+1);
     }catch(...){
         throw StringUtilsException("appendVectBuffer: a : Data error.");
     }
  }
  
  void appendVectBuffer(vector<uint8_t>& buffer, const uint8_t* orig, 
                        size_t len, size_t start, size_t stop) anyexcept{

     if(start > len-1 || stop > len-1 || len==0)
        throw StringUtilsException("appendVectBuffer: b : Invalid index merging vect and buffer of unsigned.");
     
     uint32ToUChars(buffer, safeUint32(len));
  
     try{ 
         buffer.insert(buffer.end(), orig, orig+stop+1);
     }catch(...){
         throw StringUtilsException("appendVectBuffer: b : Data error.");
     }
  }
  
  void appendVectBuffer(vector<uint8_t>& buffer,
                                     const vector<uint8_t>& orig) anyexcept{
     if(orig.size() == 0)
        throw StringUtilsException("appendVectBuffer: c : Invalid index merging vect and vect.");
  
     uint8_t  mask     { 0x80 },
              positive { static_cast<uint8_t>(orig[0] & mask ) };
     uint32ToUChars(buffer, safeUint32(orig.size() + (positive != 0?1:0)) );
  
     try{ 
        if(positive != 0) buffer.push_back(0);
        buffer.insert(buffer.end(), orig.cbegin(), orig.cend());
     }catch(...){
        throw StringUtilsException("appendVectBuffer: c : Data error.");
     }
  }
  
  void appendVectBuffer(vector<uint8_t>& buffer, const vector<uint8_t>& orig, size_t start, 
                        size_t removePad) anyexcept{

     if(orig.size() == 0) throw StringUtilsException("appendVectBuffer: d : Invalid index merging vect and vect.");
  
     uint32ToUChars(buffer, safeUint32(orig.size() - start - removePad));
  
     try{ 
         buffer.insert(buffer.end(), (orig.cbegin() + safePtrdiff(start)), 
                      (orig.cend() - safePtrdiff(removePad)));
     }catch(...){
         throw StringUtilsException("appendVectBuffer: d : Data error.");
     }
  }
  
  void  trace(const char* header, const uint8_t* buff, const size_t size,
              size_t begin, size_t end) noexcept{
     cerr << header << "\n\n";
  
     bool last  { false }, 
          first { false };
     for (size_t i{ 0 }; i < size; i += 16) {
        cerr << setfill('0') << setw(5) << dec << i << ":  ";
        for (size_t j{ i }; j < i + 16; j++) {
           if(end !=0){
              if(j == begin ){cerr <<  "\033[7m"; first = true;}
              if(j == end   ){cerr <<  "\033[0m"; last  = true;}
           }
           if(j < size)
              cerr << setfill('0') << setw(2) << hex 
                        << static_cast<int>(buff[j]) << " ";
           else cerr << "   ";
        }
        if(first){cerr <<  "\033[0m"; }
        cerr << " ";
        for (size_t j{i}; j < i + 16; j++) {
           if(end !=0){
              if((last || j == begin)){cerr <<  "\033[7m"; last  = false; }
              if(j == end            ){cerr <<  "\033[0m"; last  = false; }
           }
           if(j < size){
              if((buff[j] > 31) && (buff[j] < 128) && (buff[j] != 127))
                 cerr << buff[j] ;
              else cerr << "." ;
           }
        }
        first = false;
        cerr << '\n';
     }
     cerr << "\n\n";
  }
  
  void trace(string header) noexcept{
     cerr << header << "\n\n";
  }

  void trace(string header, const vector<uint8_t>* buff,
             size_t begin, size_t end, size_t max) noexcept{
     cerr << header << "\n\n";

     size_t len    { max ? max : buff->size() };
     bool   last   { false }, 
            first  { false };
     for (size_t i{0}; i < len; i += 16) {
        cerr << setfill('0') << setw(5) << dec << i << ":  ";
        for (size_t j{i}; j < i + 16; j++) {
           if(end !=0){
              if(j == begin ){cerr <<  "\033[7m"; first = true;}
              if(j == end   ){cerr <<  "\033[0m"; last  = true;}
           }
           if(j < len)
              cerr << setfill('0') << setw(2) << hex 
                   << static_cast<int>(buff->at(j)) << " ";
           else cerr << "   ";
        }
        if(first){cerr <<  "\033[0m"; }
        cerr << " ";
        for (size_t j{i}; j < i + 16; j++) {
           if(end !=0){
              if(last && !first   ){cerr << "\033[7m"; last  = false; }
              if(j == begin       ){cerr << "\033[7m"; first = false; }
              if(j == end         ){cerr << "\033[0m"; last  = false; }
           }
           if(j < len){
              if((buff->at(j) > 31) && (buff->at(j) < 128) && (buff->at(j) != 127))
                 cerr << buff->at(j) ;
              else cerr << "." ;
           }
        }
        first = false;
        cerr << '\n';
     }
     cerr << "\n\n";
  }

  template<typename T> 
  void addVarLengthDataString(const T& item, vector<uint8_t>& target) anyexcept
       requires is_constantIterable<T>
   {
        size_t len { item.size() };
        uint32ToUChars(target, static_cast<uint32_t>(len));
        try{
            if(len > 0) target.insert(target.end(), item.cbegin(), item.cend());
        }catch(...){
            throw StringUtilsException("addVarLengthDataString: Data error.");
        }
  }
  
  void addVarLengthDataCCharStr(const char* item, vector<uint8_t>& target) anyexcept{
     size_t len { strlen(item) };
     uint32ToUChars(target, safeUint32(len));
     try{
         if(len > 0) target.insert(target.end(), item, item+len);
     }catch(...){
         throw StringUtilsException("addVarLengthDataCCharStr: Data error.");
     }
  }
  
  size_t insVarLengthDataString(const string item, size_t start, vector<uint8_t>& target) anyexcept{
     size_t len { item.size() };
     if( len == 0 )
         throw StringUtilsException("insVarLengthDataString: Attempt to use an empty string.");

     uint32ToUChars(target.data()+start, safeUint32(len));
     insArrayVals(item, 0, target, sizeof(uint32_t));
  
     return len + sizeof(uint32_t);
  }

  template <typename T> 
  size_t getVariableLengthRawValue(const vector<uint8_t>& index, size_t offset, T& destination) anyexcept
      requires is_iterable<T> 
  {
        uint8_t   check;
        try{ 
            check = index.at(offset + sizeof(uint32_t) - 1);
        }catch(...){
            throw StringUtilsException("getVariableLengthRawValue: Invalid field length index.");
        }

        uint32_t   length { charToUint32(index.data() + offset) };

        try{ 
            if(length >0) check = index.at(length -1);
        }catch(...){
            throw StringUtilsException(string("getVariableLengthRawValue: Invalid field length :") 
                                      + to_string(length) + " elem: " + to_string(check));
        }

        try{
           if(length > 0){
                 destination.insert(destination.end(), index.begin() + safePtrdiff(sizeof(uint32_t) + offset),
                                    index.begin() + safePtrdiff(sizeof(uint32_t) + offset + length));
           }else{
                 destination.push_back(0);
                 TRACE(" ** Parsed an empty Value." ); 
           }
        }catch(...){
            throw StringUtilsException("getVariableLengthRawValue: a : Data error.");
        }
        return length + sizeof(uint32_t);
  }
  
  size_t getVariableLengthRawValue(const vector<uint8_t>& index, size_t offset,
                                   vector<uint8_t> destination[], int item) anyexcept{
     uint8_t   check;
     try{ 
         check = index.at(offset + sizeof(uint32_t) - 1);
     }catch(...){
         throw StringUtilsException("getVariableLengthRawValue - item: Invalid field length index.");
     }

     uint32_t       length { charToUint32(index.data() + offset) };

     try{ 
         if(length >0) check = index.at(length -1);
     }catch(...){
         throw StringUtilsException(string("getVariableLengthRawValue - item: Invalid field length :") 
                                   + to_string(length) + " elem: " + to_string(check));
     }

     try{
        if(length > 0){
              destination[item].insert(destination[item].end(), 
                                       index.begin() + safePtrdiff(sizeof(uint32_t) + offset), 
                                       index.begin() + safePtrdiff(sizeof(uint32_t) + offset + length));
        }else{
              destination[item].push_back(0);
              TRACE(" ** Empty Value: " + to_string(item)); 
        }
     }catch(...){
         throw StringUtilsException("getVariableLengthRawValue: b : Data error.");
     }
     return length + sizeof(uint32_t);
  }
  
  size_t getVariableLengthValueCsv(vector<uint8_t>& index, vector<char>& buff,
                                   vector<string>* algorithmStrings, int item, 
                                   size_t offset) anyexcept{
     uint8_t   check;
     try{ 
         check = index.at(offset + sizeof(uint32_t) - 1);
     }catch(...){
         throw StringUtilsException("getVariableLengthValueCsv: Invalid field length index.");
     }

     uint32_t       length  {    charToUint32(index.data() + offset) };

     try{ 
         if(length >0) check = index.at(length -1);
     }catch(...){
         throw StringUtilsException(string("getVariableLengthValueCsv: Invalid field length :") 
                                   + to_string(length) + " elem: " + to_string(check));
     }

     try{
        fill(buff.begin(), buff.end(), 0);
        copy(index.begin() + safePtrdiff(offset + sizeof(uint32_t)), 
             index.begin() + safePtrdiff(offset + sizeof(uint32_t) + length),
             buff.begin());
        if(length > 0){
           TRACE("* Parsed CSV Values: "); 
           char*          flag {    strtok(buff.data(), ",") };
           while(flag != nullptr){
              algorithmStrings[item].push_back(flag);
              TRACE((" ** Value " + to_string(item) + " : ").c_str(), 
                     reinterpret_cast<const uint8_t*>(flag), strlen(flag)); 
              flag = strtok(nullptr, ",");
           }
        }else{
              TRACE(" ** Empty Value: " + to_string(item) ); 
              algorithmStrings[item].push_back("");
        }
     }catch(...){
         throw StringUtilsException("getVariableLengthValueCsv: a : Data error.");
     }
     return length + sizeof(uint32_t);
  }

  size_t getVariableLengthValueCsv(vector<uint8_t>& index, vector<char>& buff,
                                   set<string>* algorithmStrings, int item, 
                                   size_t offset) anyexcept{
     uint8_t   check;
     try{ 
         check = index.at(offset + sizeof(uint32_t) - 1);
     }catch(...){
         throw StringUtilsException("getVariableLengthValueCsv: Invalid field length index.");
     }

     uint32_t       length  {    charToUint32(index.data() + offset) };

     try{ 
         if(length >0) check = index.at(length -1);
     }catch(...){
         throw StringUtilsException(string("getVariableLengthValueCsv: Invalid field length :") 
                                   + to_string(length) + " elem: " + to_string(check));
     }

     try{
        fill(buff.begin(), buff.end(), 0);
        copy(index.begin() + safePtrdiff(offset + sizeof(uint32_t)),
             index.begin() + safePtrdiff(offset + sizeof(uint32_t) + length),
             buff.begin());
        if(length > 0){
           TRACE("* Parsed CSV Values: "); 
           char*          flag {    strtok(buff.data(), ",") };
           while(flag != nullptr){
              algorithmStrings[item].insert(flag);
              TRACE((" ** Value " + to_string(item) + " : ").c_str(), 
                     reinterpret_cast<const uint8_t*>(flag), strlen(flag)); 
              flag = strtok(nullptr, ",");
           }
        }
     }catch(...){
         throw StringUtilsException("getVariableLengthValueCsv: b : Data error.");
     }

     return length + sizeof(uint32_t);
  }
  
  size_t getVariableLengthSingleBignum(const vector<uint8_t>& index, size_t offset,  BIGNUM* keyAndSign) anyexcept{
     vector<uint8_t>        buff;

     uint8_t     check;
     try{ 
         check = index.at(offset + sizeof(uint32_t) - 1);
     }catch(...){
         throw StringUtilsException("getVariableLengthSingleBignum: Invalid field length index.");
     }

     uint32_t    length { charToUint32(index.data() + offset) };

     try{ 
         if(length >0) check = index.at(length -1);
     }catch(...){
         throw StringUtilsException(string("getVariableLengthSingleBignum: Invalid field length :") 
                                   + to_string(length) + " elem: " + to_string(check));
     }

     try{
        buff.insert(buff.end(), index.begin() + safePtrdiff(offset + sizeof(uint32_t)), 
                    index.begin() + safePtrdiff(offset + sizeof(uint32_t) + length));
     }catch(...){
         throw StringUtilsException("getVariableLengthSingleBignum: Data error.");
     }
  
     if(BN_bin2bn(buff.data(), safeInt(length), keyAndSign ) == nullptr)
         throw StringUtilsException("Can't convert binary field of the packet to bignum.");
  
     return length + sizeof(uint32_t);
  }

  template <typename T> 
  void insArrayVals(const T& orig, size_t origOffset, vector<uint8_t>& dest, size_t destOffset) anyexcept
       requires is_iterable<T>
  {
     size_t origSize { orig.size() },
            destSize { dest.size() };
     if( ((origSize - origOffset) > (destSize - destOffset)) ||
               origSize == 0                                 ||
               destSize == 0){
         throw StringUtilsException("InsArrayVals: attempt to use invalid indexes.");
     }
     try{
        dest.insert(dest.begin()  + static_cast<ptrdiff_t>(destOffset),
                    orig.begin()  + static_cast<ptrdiff_t>(origOffset), 
                    orig.end()
        );
     }catch(...){
         throw StringUtilsException("insArrayVals: Data error.");
     }
  }
  
  template<typename T, typename U> 
  void decodeB64(const T& in, U& out) anyexcept
     requires is_constantIterable<T> && is_constantIterable<U>{
         #ifdef __GNUC__
         #pragma GCC diagnostic push
         #pragma GCC diagnostic ignored "-Wtype-limits"
         #endif

         try{
            out.resize( [&in]() -> size_t { auto i{in.cbegin()}; auto j{i}; 
                                            for(; *i != 255 && i!= in.cend(); ++i); 
                                            return ( ((static_cast<size_t>(i-j) + 2) / 4) * 3); }()
                       );
         }catch(...){
            throw StringUtilsException("decodeB64: Data error.");
         }

         #ifdef __GNUC__
         #pragma GCC diagnostic pop
         #endif
  
         auto i{in.cbegin()}; auto j{out.begin()};
         for(; i<in.cend()-4; i+=4, j+=3){
                 *j      = static_cast<uint8_t>(checkTable[static_cast<size_t>(*i)]     << 2 | 
                           checkTable[static_cast<size_t>(*(i+1))] >> 4);
                 *(j+1)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+1))] << 4 | 
                           checkTable[static_cast<size_t>(*(i+2))] >> 2);
                 *(j+2)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+2))] << 6 | 
                           checkTable[static_cast<size_t>(*(i+3))]     );
         }
  
         if(i < (in.cend() - 1))
                 *j      = static_cast<uint8_t>(checkTable[static_cast<size_t>(*i)]     << 2 | 
                           checkTable[static_cast<size_t>(*(i+1))] >> 4);
         if(i < (in.cend() - 2))
                 *(j+1)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+1))] << 4 | 
                           checkTable[static_cast<size_t>(*(i+2))] >> 2);
         if(i < (in.cend() - 3))
                 *(j+2)  = static_cast<uint8_t>(checkTable[static_cast<size_t>(*(i+2))] << 6 | 
                           checkTable[static_cast<size_t>(*(i+3))]     );
  }

  template<typename T, typename U> 
  void encodeB64(const T& in, U& out) anyexcept 
     requires is_constantIterable<T> && is_constantIterable<U>{
         try{
             out.resize((in.size() + 2) / 3 * 4);
         }catch(...){
            throw StringUtilsException("encodeB64: Data error.");
         }
  
          auto i{in.cbegin()}; auto j{out.begin()};
          for(; i<in.cend()-2; i+=3, j+=4){
                  *j     = convTable[(*i >> 2) & 0x3F];
                  *(j+1) = convTable[static_cast<size_t>(((*i     & 0x3) << 4) | 
                                                             static_cast<int>(((*(i+1) & 0xF0) >> 4 )))];
                  *(j+2) = convTable[static_cast<size_t>(((*(i+1) & 0xF) << 2) | 
                                                             static_cast<int>(((*(i+2) & 0xC0) >> 6 )))];
                  *(j+3) = convTable[  *(i+2) & 0x3F];
          }
  
          if(i < in.cend()){
                  *j     = convTable[(*i >> 2) & 0x3F];
                  if(i == (in.cend() -1)){
                          *(j+1) = convTable[static_cast<size_t>((*i  & 0x3) << 4)];
                          *(j+2) = '=';
                  }else{
                          *(j+1) = convTable[static_cast<size_t>((*i      & 0x3) << 4 |
                                                             static_cast<int>(((*(i+1) & 0xF0) >> 4 )))];
                          *(j+2) = convTable[static_cast<size_t>(((*(i+1) & 0xF) << 2))];
                  }
                  *(j+3) = '=';
          }
  }

  void encodeHex(const vector<uint8_t>& in, vector<uint8_t>& out) anyexcept{
     const uint8_t hexConv[]  {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
     try{
        for(auto i{in.cbegin()}; i != in.cend(); ++i){
           out.insert(out.end(), hexConv[ *i >> 4     ]);
           out.insert(out.end(), hexConv[ *i &  0x0F  ]);
        }
     }catch(...){
        throw StringUtilsException("encodeHex: Data error.");
     }
  }

  void getPassword(vector<uint8_t>& pwd) anyexcept{
     struct termios   termOld, termNew;
     tcgetattr(STDIN_FILENO, &termOld);
     termNew          = termOld;
     termNew.c_lflag  &= static_cast<unsigned long>(~(ICANON | ECHO));
     uint8_t          currChar;
     fd_set           readfds;
  
     cerr << "Password:" << '\n';
  
     if(tcsetattr(STDIN_FILENO, TCSANOW, &termNew) == -1)
        throw StringUtilsException("getPassword: a : Can't deactivate terminal echo.");
 
     ssize_t status;
     while(true){
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO,      &readfds);

        if(select(STDIN_FILENO+1, &readfds, nullptr, nullptr, nullptr) < 0)
           throw StringUtilsException(string("getPassword: a :  Password loop: ") + strerror(errno));

        status = read(STDIN_FILENO, &currChar, 1);
        if(status < 0 )
           throw StringUtilsException("getPassword: a : Can't read stdin.");
        if(status == 1){
           if(currChar == '\n' ) break;
           try{
              pwd.push_back(currChar);
           }catch(...){
              throw StringUtilsException("getPassword: a : Data error.");
           }
        }
     }
  
     if(tcsetattr(STDIN_FILENO, TCSANOW, &termOld) == -1)
        throw StringUtilsException("getPassword: Can't activate terminal echo.");
  }
  
  void getPassword(vector<uint8_t>& pwd, struct termios* oldTerm, 
                   struct termios* newTerm) anyexcept{
     *newTerm           =  *oldTerm;
     newTerm->c_lflag   &= static_cast<unsigned long>(~(ICANON | ECHO));
     uint8_t           currChar;
     fd_set            readfds;
  
     cerr << "Password:" << '\n';
  
     if(tcsetattr(STDIN_FILENO, TCSANOW, newTerm) == -1)
        throw StringUtilsException("getPassword: b : Can't deactivate terminal echo.");
 
     ssize_t status;
     while(true){
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO,      &readfds);

        if(select(STDIN_FILENO+1, &readfds, nullptr, nullptr, nullptr) < 0)
           throw StringUtilsException(string("getPassword: b : Password loop: ") + strerror(errno));

        status = read(STDIN_FILENO, &currChar, 1);
        if(status < 0 )
           throw StringUtilsException("getPassword: b : Can't read stdin.");
        if(status == 1){
           if(currChar == '\n' ) break;
           try{
              pwd.push_back(currChar);
           }catch(...){
              throw StringUtilsException("getPassword: b : Data error.");
           }
        }
     }
  
     if(tcsetattr(STDIN_FILENO, TCSANOW, oldTerm) == -1)
        throw StringUtilsException("getPassword: b : Can't activate terminal echo.");
  }
  
  void* secureZeroing(void *orig, size_t len) noexcept{
     volatile uint8_t* ptr { reinterpret_cast<volatile uint8_t*>(orig) };
     while (len--) *ptr++ = 0; 
     return orig;
  }

  template<typename T>
  void loadFileMem(string fileName, T& dest, bool terminator) anyexcept
      requires is_rawdata_accessible<T>
  {
    struct stat fileAttr;
    int         fd { open(fileName.c_str(), O_RDONLY) };
        if(fd == -1)
                throw(StringUtilsException(string("loadFileMem: Can't open file: ") + fileName));

        if(fstat(fd, &fileAttr) != 0)
                throw(StringUtilsException(string("loadFileMem: Can't read file attributes: ") + fileName));
     
        size_t bytes   { safeSizeT(fileAttr.st_size + (terminator ? 1 : 0)) }; 
         if(bytes == 0)
                throw(StringUtilsException(string("loadFileMem: Error reading file, too big: .") + fileName));

        try{
            dest.resize(bytes);
            if(terminator) dest[bytes -1] = 0;
            else dest.push_back(0);
        }catch(...){
           throw StringUtilsException("loadFileMem: Data error.");
        }

        if( read(fd, dest.data(), bytes) == -1 ) 
           throw(StringUtilsException(string("Error reading file: .") + fileName));
        close(fd);
  }

  #ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wsign-compare"
  #pragma GCC diagnostic ignored "-Wtype-limits"
  #endif

  #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wundefined-func-template"
  #endif

  template void   encodeB64(const vector<uint8_t>& in, string& out)                         anyexcept;
  template void   decodeB64(const string& in, vector<uint8_t>& out)                         anyexcept;
  template void   insArrayVals(const vector<uint8_t>& orig, size_t origOffset, 
                               vector<uint8_t>& dest, size_t destOffset)                    anyexcept;
  template void   addVarLengthDataString(const string& item,
                                         vector<uint8_t>& target)                           anyexcept;
  template void   addVarLengthDataString(const vector<uint8_t>& item,
                                         vector<uint8_t>& target)                           anyexcept; 
  template size_t getVariableLengthRawValue(const vector<uint8_t>& index,
                                            size_t offset, string& destination)             anyexcept;
  template size_t getVariableLengthRawValue(const vector<uint8_t>& index,
                                            size_t offset, vector<uint8_t>&destination)     anyexcept;
  template void   loadFileMem(string fileName, vector<uint8_t>& dest, 
                              bool terminator)                                              anyexcept;

  #ifdef __GNUC__
  #pragma GCC diagnostic pop
  #endif

  #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
  #pragma clang diagnostic pop
  #endif

}
