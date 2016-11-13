bin_PROGRAMS   = tssh
dist_man_MANS  = ../doc/tssh.1

nobase_include_HEADERS   = ../include/Crypto.hpp ../include/Inet.hpp ../include/Main.hpp ../include/StringUtils.hpp ../include/Tssh.hpp ../include/Types.hpp
tssh_SOURCES = Main.cpp InetImpl.cpp StringUtilsImpl.cpp Tssh.cpp CryptoImpl.cpp TypesImpl.cpp

TypesImpl.o : CXXFLAGS += -fpermissive

