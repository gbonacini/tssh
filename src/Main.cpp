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

#include <Tssh.hpp>
#include <Main.hpp>
#include <config.h> 

using namespace std;
using namespace tssh;

int main(int argc, char **argv){
   const char *SSH_PORT   { "22" };
   string      usr,
               port,
               identityFile,
               host;
   bool        noTTY   { false };
   #ifndef NOTRACE
   const char  flags[] { "l:p:i:hdTV" };
   #else
   const char  flags[] { "l:p:i:hTV" };
   #endif

   opterr = 0;
   int c;
   while ((c = getopt(argc, argv, flags)) != -1){
      switch (c){
         case 'l':
            usr = optarg;
         break;
         case 'p':
            port = optarg;
         break;
         case 'i':
            identityFile = optarg;
         break;
         #ifndef NOTRACE
         case 'd':
            stringutils::setDebug(true);
         break;
         #endif
         case 'T':
            noTTY = true;
         break;
         case 'V':
            if(argc != 2) paramError(argv[0], "-V parameter must be present alone.");
            versionInfo();
         default:
            cerr << "Invalid parameter.\n\n";
         [[fallthrough]];
         case 'h':
            paramError(argv[0], nullptr);
      }
   }

   if(usr.size() == 0 || optind != argc-1)
         paramError(argv[0], "Invalid command.");

   if(port.size() == 0)
         port = SSH_PORT;

   host = argv[optind];

   try{
      SshConnection ssh(usr, host, port, noTTY,identityFile);
      ssh.getShell();

      ssh.disconnect();
      
   } catch(stringutils::StringUtilsException& e){
      cerr << "Exception Rised: " << e.what() << '\n';
   } catch(inet::InetException& e){
      cerr << "Exception Rised: " << e.what() << '\n';
   } catch(crypto::CryptoException& e){
      cerr << "Exception Rised: " << e.what() << '\n';
   } catch(typeutils::TypesUtilsException& e){
      cerr << "Exception Rised: " << e.what() << '\n';
   } catch(...){
      cerr << "Unexpected Exception Rised. \n";
   }

   return 0;
}

void paramError(const char* progname, const char* err){
   if(err != nullptr)
      cerr << err << "\n\n";
   cerr << "tssh - a test ssh client. GBonacini - (C) 2016-2023   \n";
   cerr << "Syntax: \n";
   #ifndef NOTRACE
   cerr << "       " << progname << " [-p port] [-l user] [-i identity] [-T] [-d] host | [-h] | [-V]\n";
   #else
   cerr << "       " << progname << " [-p port] [-l user] [-i identity] [-T] host | [-h] | [-V]\n";
   #endif
   cerr << "       " << "-T doesn't allocate a pty.\n";
   #ifndef NOTRACE
   cerr << "       " << "-d enable debug mode.\n";
   #endif
   cerr << "       " << "-h print this help message.\n";
   cerr << "       " << "-V version information.\n";
   exit(1);
}

void versionInfo(void){
   cerr << PACKAGE << " version: " VERSION << '\n';
   exit(1);
}
