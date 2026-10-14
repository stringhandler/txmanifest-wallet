// shrincs-signer: a SHRINCS-L key from a seed file, and stateful signatures over 32-byte
// messages, printed as the witness values examples/pq_shrincs/shrincs_spend.simf reads.
//
//   shrincs-signer new    --seed FILE --state FILE   write a fresh seed, and a state file
//                                                    at q = 0
//   shrincs-signer pubkey --seed FILE                print PK (PK.seed || PK.root)
//   shrincs-signer sign   --seed FILE --state FILE --msg HEX
//                                                    print {"SIG": ..., "OTHER_ROOT": ...}
//   shrincs-signer sign-raw --seed FILE --q N --msg HEX
//                                                    TEST KEYS ONLY: sign at leaf index N,
//                                                    keeping no state, and print the raw
//                                                    signature split into its fields
//
// A thin driver around shrincs-cpp (see the Makefile for the commit); the cryptography is
// all upstream's. Phase 0 only: the plan is for signers to run inside the wallet.
//
// Stateful signing only. Each signature uses the next leaf index q, and reusing one lets
// anyone forge, so the state file is rewritten and synced *before* the signature is
// printed: a crash can waste an index, never reuse one. `sign` refuses to run without a
// state file rather than assume q = 0, because a lost state file is exactly how an index
// gets reused.

#include "shrincs.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

using namespace Parameters;
using namespace SHRINCS;

static constexpr size_t SEED_LEN = 3 * N;  // SK.seed || SK.prf || PK.seed

[[noreturn]] static void die(const std::string& msg) {
    fprintf(stderr, "shrincs-signer: %s\n", msg.c_str());
    exit(1);
}

static std::string hex(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(2 * n);
    for (size_t i = 0; i < n; i++) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}

static std::vector<unsigned char> unhex(const std::string& s, size_t want, const char* what) {
    std::string h = s;
    if (h.rfind("0x", 0) == 0) h = h.substr(2);
    while (!h.empty() && (h.back() == '\n' || h.back() == '\r' || h.back() == ' ')) h.pop_back();
    if (h.size() != 2 * want) die(std::string(what) + ": expected " + std::to_string(want) + " bytes of hex");
    std::vector<unsigned char> out(want);
    for (size_t i = 0; i < want; i++) {
        unsigned int b;
        if (sscanf(h.c_str() + 2 * i, "%2x", &b) != 1) die(std::string(what) + ": not hex");
        out[i] = (unsigned char)b;
    }
    return out;
}

static std::string read_file(const std::string& path) {
    FILE* f = fopen(path.c_str(), "r");
    if (!f) die("cannot read " + path + ": " + strerror(errno));
    std::string s;
    char buf[256];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
    fclose(f);
    return s;
}

// Write `contents` to `path` durably: a temporary file, fsync, then rename over the old one.
static void write_file_synced(const std::string& path, const std::string& contents, mode_t mode) {
    std::string tmp = path + ".tmp";
    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) die("cannot write " + tmp + ": " + strerror(errno));
    if (write(fd, contents.data(), contents.size()) != (ssize_t)contents.size()) die("short write to " + tmp);
    if (fsync(fd) != 0) die("cannot sync " + tmp + ": " + strerror(errno));
    close(fd);
    if (rename(tmp.c_str(), path.c_str()) != 0) die("cannot replace " + path + ": " + strerror(errno));
}

static bool exists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

static std::string flag(int argc, char** argv, const char* name, bool required = true) {
    for (int i = 2; i + 1 < argc; i++)
        if (strcmp(argv[i], name) == 0) return argv[i + 1];
    if (required) die(std::string("missing ") + name);
    return "";
}

static void restore(const std::string& seed_path, PublicKey& pk, SecretKey& sk, State& state) {
    auto seed = unhex(read_file(seed_path), SEED_LEN, "seed file");
    shrincs_restore(seed.data(), pk, sk, state);
}

static int cmd_new(int argc, char** argv) {
    std::string seed_path = flag(argc, argv, "--seed");
    std::string state_path = flag(argc, argv, "--state");
    if (exists(seed_path)) die(seed_path + " exists; refusing to overwrite a key");
    if (exists(state_path)) die(state_path + " exists; refusing to reset a key's state");
    unsigned char seed[SEED_LEN];
    generate_random_bytes(seed, SEED_LEN);
    write_file_synced(seed_path, hex(seed, SEED_LEN) + "\n", 0600);
    write_file_synced(state_path, "0\n", 0600);
    fprintf(stderr, "wrote %s and %s (q = 0)\n", seed_path.c_str(), state_path.c_str());
    return 0;
}

static int cmd_pubkey(int argc, char** argv) {
    PublicKey pk;
    SecretKey sk;
    State state;
    restore(flag(argc, argv, "--seed"), pk, sk, state);
    printf("0x%s%s\n", hex(pk.seed.data(), N).c_str(), hex(pk.root.data(), N).c_str());
    return 0;
}

static int cmd_sign(int argc, char** argv) {
    std::string state_path = flag(argc, argv, "--state");
    auto msg = unhex(flag(argc, argv, "--msg"), 32, "--msg");
    if (!exists(state_path)) die(state_path + " does not exist; `new` creates it with the seed");

    PublicKey pk;
    SecretKey sk;
    State state;
    restore(flag(argc, argv, "--seed"), pk, sk, state);

    char* end = nullptr;
    std::string text = read_file(state_path);
    unsigned long last_q = strtoul(text.c_str(), &end, 10);
    if (end == text.c_str()) die(state_path + ": expected the last leaf index used, a number");
    uint32_t q = (uint32_t)last_q + 1;
    // Leaves 1..HSF are the unbalanced tree's; HSF + 1 is its last leaf, the one beside
    // the stateless root (the verifier's `key_idx == HSF + 1` case).
    if (q > HSF + 1) die("this key has used all " + std::to_string(HSF + 1) + " stateful signatures");

    // Record the index before the signature exists.
    write_file_synced(state_path, std::to_string(q) + "\n", 0600);

    state.q = (uint32_t)last_q;
    state.valid = true;
    unsigned char* sig = shrincs_sign_stateful(msg.data(), sk, state);
    uint32_t path_nodes = q > HSF ? HSF : q;
    uint32_t sig_len = N + WOTS_SIGN_LEN + path_nodes * N;
    if (!shrincs_verify_stateful(msg.data(), sig, sig_len, pk)) die("the signature does not verify");

    // sl_root(N) || R(R_LEN) || counter(4) || L chain values(N each) || path(N each),
    // as optimize_fors's tools/vectors_to_wit.py reads it.
    const unsigned char* p = sig;
    std::string sl_root = hex(p, N);
    p += N;
    std::string r = hex(p, R_LEN);
    p += R_LEN;
    std::string counter = hex(p, 4);
    p += 4;
    std::string chains;
    for (uint32_t i = 0; i < L; i++, p += N) chains += (i ? ", 0x" : "0x") + hex(p, N);
    std::string path;
    for (uint32_t i = 0; i < path_nodes; i++, p += N) path += (i ? ", 0x" : "0x") + hex(p, N);
    delete[] sig;

    printf("{\n  \"SIG\": \"Left(((0x%s, 0x%s, [%s]), list![%s], %u))\",\n  \"OTHER_ROOT\": \"0x%s\"\n}\n",
           r.c_str(), counter.c_str(), chains.c_str(), path.c_str(), q, sl_root.c_str());
    fprintf(stderr, "signed with leaf index q = %u; %s now records it\n", q, state_path.c_str());
    return 0;
}

// For test harnesses such as the contest runner, which sign many leaf indexes of
// published test keys. It keeps no state, so it reuses indexes freely, which is exactly
// what makes it unsafe for any key that guards coins.
static int cmd_sign_raw(int argc, char** argv) {
    auto msg = unhex(flag(argc, argv, "--msg"), 32, "--msg");
    char* end = nullptr;
    std::string q_text = flag(argc, argv, "--q");
    unsigned long q = strtoul(q_text.c_str(), &end, 10);
    if (end == q_text.c_str() || q < 1 || q > HSF + 1)
        die("--q must be a leaf index from 1 to " + std::to_string(HSF + 1));

    PublicKey pk;
    SecretKey sk;
    State state;
    restore(flag(argc, argv, "--seed"), pk, sk, state);
    state.q = (uint32_t)q - 1;
    state.valid = true;
    unsigned char* sig = shrincs_sign_stateful(msg.data(), sk, state);
    uint32_t path_nodes = q > HSF ? HSF : (uint32_t)q;
    uint32_t sig_len = N + WOTS_SIGN_LEN + path_nodes * N;
    if (!shrincs_verify_stateful(msg.data(), sig, sig_len, pk)) die("the signature does not verify");

    const unsigned char* p = sig;
    std::string sl_root = hex(p, N);
    p += N;
    std::string r = hex(p, R_LEN);
    p += R_LEN;
    std::string counter = hex(p, 4);
    p += 4;
    std::string chains, path;
    for (uint32_t i = 0; i < L; i++, p += N) chains += std::string(i ? ", " : "") + "\"" + hex(p, N) + "\"";
    for (uint32_t i = 0; i < path_nodes; i++, p += N) path += std::string(i ? ", " : "") + "\"" + hex(p, N) + "\"";

    printf("{\"kind\": \"stateful\", \"q\": %lu, \"msg\": \"%s\", \"pk\": \"%s%s\", "
           "\"pk_seed\": \"%s\", \"pk_root\": \"%s\", \"raw\": \"%s\", \"sl_root\": \"%s\", "
           "\"r\": \"%s\", \"counter\": \"%s\", \"chains\": [%s], \"path\": [%s]}\n",
           q, hex(msg.data(), 32).c_str(), hex(pk.seed.data(), N).c_str(), hex(pk.root.data(), N).c_str(),
           hex(pk.seed.data(), N).c_str(), hex(pk.root.data(), N).c_str(), hex(sig, sig_len).c_str(),
           sl_root.c_str(), r.c_str(), counter.c_str(), chains.c_str(), path.c_str());
    delete[] sig;
    return 0;
}

int main(int argc, char** argv) {
    std::string cmd = argc > 1 ? argv[1] : "";
    if (cmd == "new") return cmd_new(argc, argv);
    if (cmd == "pubkey") return cmd_pubkey(argc, argv);
    if (cmd == "sign") return cmd_sign(argc, argv);
    if (cmd == "sign-raw") return cmd_sign_raw(argc, argv);
    fprintf(stderr,
            "usage:\n"
            "  shrincs-signer new    --seed FILE --state FILE\n"
            "  shrincs-signer pubkey --seed FILE\n"
            "  shrincs-signer sign   --seed FILE --state FILE --msg HEX\n"
            "  shrincs-signer sign-raw --seed FILE --q N --msg HEX   (test keys only)\n");
    return 2;
}
