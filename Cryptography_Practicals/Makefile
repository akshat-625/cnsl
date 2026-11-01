CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra
OPENSSL_LIBS = -lcrypto

.PHONY: all clean

all: rsa_demo rsa_benchmark custom dh sha1 signature image

rsa_demo: rsa_demo.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

rsa_benchmark: rsa_benchmark.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(OPENSSL_LIBS)

custom: custom.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

dh: dh.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

sha1: sha1.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(OPENSSL_LIBS)

signature: signature.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(OPENSSL_LIBS)

image: image.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ $(OPENSSL_LIBS)

clean:
	rm -f rsa_demo rsa_benchmark custom dh sha1 signature image encrypted.bin key.bin recovered.jpg
