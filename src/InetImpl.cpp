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

#include <Inet.hpp>

namespace inet {

   using std::cerr;
   using std::endl;
   using std::string;
   using typeutils::safeSsizeT;
   using typeutils::safeSizeT;
   
   InetException::InetException(int errNum){
      errorCode               = errNum;
      errorMessage            = "None";
   }
   
   InetException::InetException(string& errString){
      errorMessage            = errString;
      errorCode               = 0;
   }
   
   InetException::InetException(string&& errString){
      errorMessage            = move(errString);
      errorCode               = 0;
   }
   
   InetException::InetException(int errNum, string errString){
      errorMessage            = errString;
      errorCode               = errNum;
   }
   
   string InetException::what() const noexcept(true){
      return errorMessage;
   }
   
   Inet::Inet(readFunc rFx, writeFunc wFx) : result(nullptr), bufferPtr(nullptr), 
                                             tvMin{3,0}, tvMax{10,0}, nfds(-1) {
      FD_ZERO(&fdset);
      memset(&handler, 0, sizeof(Handler));
      memset(&hints, 0, sizeof(struct addrinfo));
   
      socketFd                = -1;

      hints.ai_socktype       = SOCK_STREAM;
      hints.ai_family         = AF_INET;
      hints.ai_flags          = AI_NUMERICSERV ;
   
      rFunc                   = rFx != nullptr ? rFx : readSocket;
      wFunc                   = wFx != nullptr ? wFx : writeSocket;
   }

   Inet::~Inet(){}

   int Inet::socketFd;
   
   void Inet::setTimeoutMin(long int seconds, int useconds) noexcept(true){
      tvMin.tv_sec            = seconds;
      tvMin.tv_usec           = useconds;
   }
   
   void Inet::setTimeoutMax(long int seconds, int useconds) noexcept(true){
      tvMax.tv_sec            = seconds;
      tvMax.tv_usec           = useconds;
   }
   
   ssize_t Inet::readSocket(Handler* fDesc, void *buf, size_t len) noexcept(true){
      if(len > 0)
         return ::read(*(static_cast<int const *>(fDesc->peerFd)), buf, static_cast<size_t>(len));
      else
         return EINVAL;
   }
   
   ssize_t Inet::writeSocket(Handler* fDesc, void *buf, size_t len) noexcept(true){
      if(len > 0)
         return ::write(*(static_cast<int const *>(fDesc->peerFd)), buf, static_cast<size_t>(len));
      else
         return EINVAL;
   }
   
   size_t Inet::readLineTimeout(size_t maxSize, char sep, Handler *hdlr) noexcept(false){
      char     buff[2]        = {0,0};
      Handler  *localHandler  = hdlr ? hdlr : &handler;
      currentLine             = "";
      errno                   = 0;

      for(;;){
         FD_ZERO(&fdset); 
         FD_SET(*(localHandler->peerFd), &fdset);

         if(*(localHandler->peerFd) > nfds)
            nfds = *(localHandler->peerFd) + 1;

         ssize_t ret=::select(nfds, &fdset, nullptr, nullptr, &tvMin);
         switch(ret){
            case -1:
               throw InetException("readLineTimeout: Select Error.");
            case  0:
               throw InetException("readLineTimeout: Select Timeout.");
            default:
               ret = (*rFunc)(localHandler, buff, 1);
               switch(ret){
                  case 1:
                     currentLine.append(static_cast<const char*>(buff));
                     if(buff[0] == sep) return currentLine.size();
                     if(maxSize > 0 && currentLine.size() == (maxSize + 1))
                        throw InetException(string("readLine: Line too long."));
                  break;
                  case 0:
                     throw InetException(string("readLineTimeout: Connection Closed by peer."));
                  default:
                     throw InetException(string("readLineTimeout: Read error: ") + strerror(errno));
              }
        }
     }
   }
   
   size_t Inet::readLine(size_t maxSize, char sep, Handler* hdlr) noexcept(false){
      char     buff[2]        = {0,0};
      Handler  *localHandler  = hdlr ? hdlr : &handler;
      currentLine             = "";

      errno=0;
      for(;;){
         ssize_t ret = (*rFunc)(localHandler, buff, 1);
         switch(ret){
            case 1:
               currentLine.append(static_cast<const char*>(buff));
               if(buff[0] == sep) return currentLine.size();
               if(maxSize > 0 && currentLine.size() == (maxSize + 1))
                  throw InetException(string("readLine: Line too long."));
            break;
            case 0:
               throw InetException(string("readLine: Connection Closed by peer."));
            default:
               throw InetException(string("readLine: Read error: ") + strerror(errno));
         }
      }
   }
   
   void Inet::addLine(string* dest) const noexcept(true){
      dest->append(currentLine);
   }
   
   bool Inet::checkHeader(string header, size_t sizeMax, char sep, bool read, 
                          bool timeout, Handler *hdlr) noexcept(false){
      if(read) timeout?(void)readLineTimeout(sizeMax, sep, hdlr) : 
                       (void)readLine(sizeMax, sep, hdlr);
      return currentLine.find(header) != string::npos ? true : false; 
   }
   
   bool Inet::checkHeaderRaw(string header) const noexcept(false){
      try{
         string temp; 
         temp.insert(temp.end(), buffer.begin(), buffer.end());
         return temp.find(header) != string::npos ? true : false;
      }catch (...){
         throw InetException("checkHeaderRaw: Unexpected data error.");
      }
   }
   
   ssize_t Inet::getReadLen(void) const noexcept(true){
      return readLen;
   }
   
   template<class T>
   void Inet::getBufferCopy(T& dest, bool append)  const noexcept(false){
      if(buffer.size() == 0)
         throw InetException("getBufferCopy: Attempt of copy an unitialized buffer.");
      try{
         if(!append) dest.clear();
         dest.insert(dest.end(), buffer.begin(), buffer.begin() + readLen);
      }catch(...){
         throw InetException("getBufferCopy: Attempt of copy Inet buffer failed.");
      }
   }
   
   ssize_t Inet::readBuffer(size_t len, Handler* hdlr, void** buff) noexcept(false){
      void**  localBuff;
      void*   indBuff;
      Handler *localHandler   = hdlr ? hdlr : &handler;
      size_t bufLen           = len ? len : buffer.size();
      if(hdlr != nullptr){
         localBuff            = buff;
      }else{
         indBuff              = buffer.data();
         localBuff            = &indBuff;
      }
   
      memset(*localBuff, 0, bufLen);
      readLen = (*rFunc)(localHandler, *localBuff, bufLen);
      if(readLen == 0)                  throw InetException("Connection was closed by the server.");
      if(readLen < 0 && errno != EINTR) throw InetException(string("readBuffer: Read error: ") + strerror(errno));

      errno   = 0;
   
      return readLen > 0 ? readLen : 0;
   }

   void Inet::setBlocking(bool onOff) noexcept(false){
      if( socketFd != -1){
           int oFlags         = fcntl(socketFd, F_GETFL);
           if(oFlags == -1) 
              throw InetException("setBlocking: Error getting descriptor settings.");
           int nFlags         = onOff ? oFlags | O_NONBLOCK : oFlags & ~O_NONBLOCK;
           if(fcntl(socketFd, F_SETFL, nFlags) == -1)
              throw InetException("setBlocking: Error setting descriptor settings.");
      }else{
         throw InetException("setBlocking: Error trying socketFd() on an invalid descriptor.");
      } 
   }

   ssize_t Inet::readBufferNb(size_t len, Handler* hdlr, void** buff) noexcept(false){
      void**  localBuff;
      void*   indBuff;
      Handler *localHandler   = hdlr ? hdlr : &handler;
      size_t bufLen           = len ? len : buffer.size();
      if(hdlr != nullptr){
         localBuff            = buff;
      }else{
         indBuff              = buffer.data();
         localBuff            = &indBuff;
      }
   
      memset(*localBuff, 0, bufLen);
      ssize_t tlen         = (*rFunc)(localHandler, *localBuff, bufLen);
      if(tlen == 0) throw InetException("Connection was closed by the server.");
      if(tlen < 1 && errno != EAGAIN && errno != EINTR)
                    throw InetException(string("readBufferNb: Read error: ") + strerror(errno));

      errno                = 0;
      readLen              = tlen > 0 ? tlen : 0;
   
      return readLen;
   }
   
   void Inet::initBuffer(size_t len) noexcept(false){
      if(len == 0) throw InetException("initBuffer: InitBuffer: Invalid buffer size");
      
      try{
         buffer.resize(len);
         bufferPtr         = buffer.data();
      }catch(...){
         throw InetException("InitBuffer: Can't initialize buffer.");
      }
   }
   
   void Inet::writeBuffer(const uint8_t* msg, size_t size, Handler* hdlr) const noexcept(false){
      Handler  *localHandler   = hdlr ? hdlr : &handler;
   
      for(size_t s=0; s<size;){
         ssize_t writeLen   = (*wFunc)(localHandler, 
                                       reinterpret_cast<void*>(const_cast<uint8_t*>(msg)), size);
         if(writeLen < 0 && errno != EINTR) 
             throw InetException(string("writeBuffer: Write error: ") + strerror(errno));
         if(writeLen > 0){
            s               += static_cast<size_t>(writeLen);
            msg             += static_cast<size_t>(writeLen);
         }
      }
      errno=0;
   }
   
   void Inet::writeBuffer(const string& msg, Handler* hdlr) const noexcept(false){
      ssize_t msgLen           = safeSsizeT(msg.size());
      Handler *localHandler    = hdlr ? hdlr : &handler;
   
      errno=0;
      for(size_t s=0; s<msg.size();){
         ssize_t writeLen = (*wFunc)(localHandler, 
                                     reinterpret_cast<void*>(const_cast<char*>(msg.c_str() + s)),
                                     safeSizeT(msgLen));
         if(writeLen < 0&& errno != EINTR) 
            throw InetException(string("Write error: ") + strerror(errno));
         if(writeLen > 0) 
            s                  += static_cast<size_t>(writeLen);
      }
      errno=0;
   }
   
   InetClient::InetClient(const char* ifc, const char* port) noexcept(false){
      int errCode  = getaddrinfo(ifc, port, &hints, &result);
      if( errCode != 0) throw InetException(string("InetClient: Getaddrinfo Error: ") + 
                                            ifc + " : " + ::gai_strerror(errCode));
      
      for(resElement=result; resElement!=nullptr; resElement=resElement->ai_next){
         socketFd=socket(resElement->ai_family, resElement->ai_socktype, resElement->ai_protocol);
         if(socketFd == -1)                        continue;
         if(connect(socketFd,resElement->ai_addr,
            resElement->ai_addrlen) == 0)          break;
      }
   
      if(resElement == nullptr) throw InetException("InetClient: Connect socket to any address failed.");
   
      static_cast<void>(freeaddrinfo(result));
      result=nullptr;
      handler.peerFd = static_cast<int*>(&socketFd);
   }
   
   void InetClient::cleanResurces(void) noexcept(true){
      if(socketFd >= 0 ){
         close(socketFd);
         socketFd=-1;
      }
      if(result != nullptr){
         static_cast<void>(freeaddrinfo(result));
         result=nullptr;
      }
      handler.peerFd = nullptr;
   }
   
   InetClient::~InetClient(void){
      cerr << "Closing lower connection." << endl;
      cleanResurces();
   }

   #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
   #pragma clang diagnostic push
   #pragma clang diagnostic ignored "-Wundefined-func-template"
   #endif

   template void Inet::getBufferCopy(std::string& dest, bool append=false)           const noexcept(false);
   template void Inet::getBufferCopy(std::vector<uint8_t>& dest, bool append=false)  const noexcept(false);

   #if defined  __clang_major__ && __clang_major__ >= 4 && !defined __APPLE__ && __clang_major__ >= 4
   #pragma clang diagnostic pop
   #endif

}
