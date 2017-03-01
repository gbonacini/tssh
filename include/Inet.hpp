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

#ifndef INET_CLASS
#define INET_CLASS

#include <unistd.h>
#include <errno.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include <iostream>
#include <string>
#include <vector>

#include <Types.hpp>
   
namespace inet{
   
   class InetException final {
      public:
         InetException(int errNum);
         InetException(std::string&  errString);
         InetException(std::string&& errString);
         InetException(int errNum, std::string errString);
         std::string what(void)                                        const noexcept(true);
      private:
         std::string errorMessage;
         int errorCode;
   };
   
   struct Handler{
      int *peerFd;
      // For future impl.
   };
   
   typedef ssize_t ( *readFunc)  ( Handler*, void*, size_t );
   typedef ssize_t ( *writeFunc) ( Handler*, void*, size_t );

   class Inet{
      public:
         Inet(readFunc rFx=nullptr, writeFunc wFx=nullptr);
         virtual  ~Inet(void);
         ssize_t  readBuffer(size_t len=0, Handler* hdlr=nullptr, 
                             void** buff=nullptr)                           noexcept(false);
         ssize_t  readBufferNb(size_t len=0, Handler* hdlr=nullptr, 
                             void** buff=nullptr)                           noexcept(false);
         size_t   readLine(size_t maxSize=0, char sep='\n', 
                           Handler* hdlr=nullptr)                           noexcept(false);
         size_t   readLineTimeout(size_t maxSize=0, char sep='\n',
                                  Handler* hdlr=nullptr)                    noexcept(false);
         void     setBlocking(bool onOff=true)                              noexcept(false);
   
         void     writeBuffer(const uint8_t* msg, size_t size, 
                              Handler* hdlr=nullptr)                  const noexcept(false);
         void     writeBuffer(const std::string& msg, 
                              Handler* hdlr=nullptr)                  const noexcept(false);
   
         static 
         ssize_t  readSocket(Handler* fDesc, 
                             void *buf,  size_t len)                        noexcept(true); 
         static
         ssize_t  writeSocket(Handler* fDesc, 
                              void *buf, size_t len)                        noexcept(true);
   
         bool     checkHeader(std::string header, size_t sizeMax=0, 
                              char sep='\n', bool read=false, 
                              bool timeout=false, 
                              Handler *hdlr=nullptr)                        noexcept(false);
         bool     checkHeaderRaw(std::string header)                  const noexcept(false);
   
         void     addLine(std::string* dest)                          const noexcept(true);
         ssize_t  getReadLen(void)                                    const noexcept(true);
         void     initBuffer(size_t len)                                    noexcept(false);
         template<class T>
         void     getBufferCopy(T& dest, bool append=false)           const noexcept(false);
   
         void     setTimeoutMin(long int seconds, int useconds=0)           noexcept(true);
         void     setTimeoutMax(long int seconds, int useconds=0)           noexcept(true);
      protected:
         static   int                socketFd;
         mutable  Handler            handler;
         ssize_t  readLen;
         struct   addrinfo           hints,
                                    *result, 
                                    *resElement;
         virtual  
         void      cleanResurces(void)                               = 0;
   
         void*                      bufferPtr;
         std::vector<uint8_t>       buffer;
         std::string                currentLine;
         readFunc                   rFunc;
         writeFunc                  wFunc;
      private:
         struct  timeval            tvMin,
                                    tvMax;
         fd_set                     fdset;
         int                        nfds;
   };

   class InetClient : public Inet{
           public:
                   InetClient(const char* ifc, const char* port) ;
                   ~InetClient(void);                                              
           private:
                   void cleanResurces(void)                                 noexcept(true)   override;
   };

   extern template 
   void Inet::getBufferCopy(std::string& dest, bool append=false)           const noexcept(false);
   extern template 
   void Inet::getBufferCopy(std::vector<uint8_t>& dest, bool append=false)  const noexcept(false);

}
   
#endif
