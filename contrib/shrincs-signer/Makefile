# shrincs-signer: a phase 0 command-line signer for examples/pq_shrincs, around shrincs-cpp.
# `make` fetches shrincs-cpp at the pinned commit into deps/ and builds bin/shrincs-signer.
# Needs a C++17 compiler and OpenSSL 3 (brew install openssl@3; apt install libssl-dev).

SHRINCS_CPP_REPO   := https://github.com/BlockstreamResearch/shrincs-cpp
# The commit whose FORS+C signatures upstream's main verifier accepts. Later commits moved
# to PORS+FP, which it rejects.
SHRINCS_CPP_COMMIT := fde3603fb4fe268a6095ca90bae3ae651fc69ff7
SHRINCS_CPP        := deps/shrincs-cpp

OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
CXX      ?= c++
# SHRINCS_L selects W=4, L=64, S=140, HSF=206, the parameters the verifier hard-codes.
# shrincs-cpp defaults to SHRINCS_B (W=256, HSF=158), whose signatures it would reject.
# `-include algorithm`: upstream's hash.cpp uses std::min without including <algorithm>,
# which GCC's headers happen to supply and libc++ (Apple clang) does not.
CXXFLAGS := -std=c++17 -O3 -Wall -Wno-deprecated-declarations -DSHRINCS_L -include algorithm \
            -I$(SHRINCS_CPP)/include $(if $(OPENSSL_PREFIX),-I$(OPENSSL_PREFIX)/include)
LDFLAGS  := $(if $(OPENSSL_PREFIX),-L$(OPENSSL_PREFIX)/lib) -lcrypto

bin/shrincs-signer: shrincs-signer.cpp $(SHRINCS_CPP)/.fetched
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) shrincs-signer.cpp $(filter-out %/main.cpp,$(wildcard $(SHRINCS_CPP)/src/*.cpp)) \
	  -o $@ $(LDFLAGS)

$(SHRINCS_CPP)/.fetched:
	rm -rf $(SHRINCS_CPP) && mkdir -p $(SHRINCS_CPP)
	cd $(SHRINCS_CPP) && git init -q && git fetch -q --depth 1 $(SHRINCS_CPP_REPO) $(SHRINCS_CPP_COMMIT) \
	  && git checkout -q FETCH_HEAD
	touch $@

clean:
	rm -rf bin deps

.PHONY: clean
