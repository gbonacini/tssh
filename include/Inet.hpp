// -----------------------------------------------------------------
// Tssh - A ssh test client. 
// Copyright (C) 2016-2021  Gabriele Bonacini
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

#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include <exception>
#include <iostream>
#include <string>
#include <vector>

#include <anyexcept.hpp>
#include <Types.hpp>
   
namespace inet{
   
   class InetException final : public std::exception {
      public:
         explicit    InetException(int errNum);
         explicit    InetException(std::string&  errString);
         explicit    InetException(std::string&& errString);
                     InetException(int errNum, std::string errString);
         const char* what(void)                                        const noexcept override;
         int         getErrorCode(void)                                const noexcept;
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
                             void** buff=nullptr)                           anyexcept;
         ssize_t  readBufferNb(size_t len=0, Handler* hdlr=nullptr, 
                             void** buff=nullptr)                           anyexcept;
         size_t   readLine(size_t maxSize=0, char sep='\n', 
                           Handler* hdlr=nullptr)                           anyexcept;
         size_t   readLineTimeout(size_t maxSize=0, char sep='\n',
                                  Handler* hdlr=nullptr)                    anyexcept;
         void     setBlocking(bool onOff=true)                              anyexcept;
   
         void     writeBuffer(const uint8_t* msg, size_t size, 
                              Handler* hdlr=nullptr)                  const anyexcept;
         void     writeBuffer(const std::string& msg, 
                              Handler* hdlr=nullptr)                  const anyexcept;
   
         static 
         ssize_t  readSocket(Handler* fDesc, 
                             void *buf,  size_t len)                        noexcept; 
         static
         ssize_t  writeSocket(Handler* fDesc, 
                              void *buf, size_t len)                        noexcept;
   
         bool     checkHeader(std::string header, size_t sizeMax=0, 
                              char sep='\n', bool read=false, 
                              bool timeout=false, 
                              Handler *hdlr=nullptr)                        anyexcept;
         bool     checkHeaderRaw(std::string header)                  const anyexcept;
   
         void     addLine(std::string* dest)                          const noexcept;
         ssize_t  getReadLen(void)                                    const noexcept;
         void     initBuffer(size_t len)                                    anyexcept;
         template<class T>
         void     getBufferCopy(T& dest, bool append=false)           const anyexcept;
   
         void     setTimeoutMin(long int seconds, int useconds=0)           noexcept;
         void     setTimeoutMax(long int seconds, int useconds=0)           noexcept;
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
                   ~InetClient(void)                                                   override;                                              
           private:
                   void cleanResurces(void)                                 noexcept   override;
   };

   extern template 
   void Inet::getBufferCopy(std::string& dest, bool append=false)           const anyexcept;
   extern template 
   void Inet::getBufferCopy(std::vector<uint8_t>& dest, bool append=false)  const anyexcept;

}
   
#endif
