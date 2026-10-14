#include "net/tls.hpp"

#include "core/crypto.hpp"
#include "core/util.hpp"

#ifdef SENTINEL_HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <filesystem>
#endif

namespace sentinel::net {

#ifdef SENTINEL_HAVE_OPENSSL

namespace {

std::string ssl_errors() {
    std::string out;
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.empty()) out += "; ";
        out += buf;
    }
    return out.empty() ? "unknown TLS error" : out;
}

std::string x509_fingerprint(X509* cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    if (!X509_digest(cert, EVP_sha256(), md, &n)) return "";
    return "sha256:" + to_hex(md, n);
}

X509* peer_certificate(SSL* ssl) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return SSL_get1_peer_certificate(ssl);
#else
    return SSL_get_peer_certificate(ssl);
#endif
}

}  // namespace

bool tls_available() { return true; }
std::string tls_library_version() { return OpenSSL_version(OPENSSL_VERSION); }

TlsContext::~TlsContext() {
    if (ctx_) SSL_CTX_free(static_cast<SSL_CTX*>(ctx_));
}

std::unique_ptr<TlsContext> TlsContext::server(const std::string& cert_file, const std::string& key_file,
                                               std::string& error) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        error = ssl_errors();
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file.c_str()) != 1) {
        error = "cannot load certificate " + cert_file + ": " + ssl_errors();
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
        error = "cannot load private key " + key_file + ": " + ssl_errors();
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        error = "private key does not match certificate";
        SSL_CTX_free(ctx);
        return nullptr;
    }
    auto t = std::unique_ptr<TlsContext>(new TlsContext());
    t->ctx_ = ctx;
    t->server_ = true;
    return t;
}

std::unique_ptr<TlsContext> TlsContext::client(const ClientTlsOptions& opt, std::string& error) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        error = ssl_errors();
        return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    if (!opt.pin_sha256.empty() || opt.insecure) {
        // Закреплённый отпечаток проверяется после рукопожатия (verify_pin) —
        // это надёжнее цепочки доверия для самоподписанного сертификата.
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        bool ok = opt.ca_file.empty() ? SSL_CTX_set_default_verify_paths(ctx) == 1
                                      : SSL_CTX_load_verify_locations(ctx, opt.ca_file.c_str(), nullptr) == 1;
        if (!ok) {
            error = "cannot load CA certificates: " + ssl_errors();
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }
    auto t = std::unique_ptr<TlsContext>(new TlsContext());
    t->ctx_ = ctx;
    t->copt_ = opt;
    return t;
}

TlsConn::~TlsConn() {
    if (ssl_) SSL_free(static_cast<SSL*>(ssl_));
}

std::unique_ptr<TlsConn> TlsConn::create(TlsContext& ctx, socket_t fd, const std::string& sni_host) {
    SSL* ssl = SSL_new(static_cast<SSL_CTX*>(ctx.native()));
    if (!ssl) return nullptr;
    SSL_set_fd(ssl, int(fd));
    if (ctx.is_server()) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
        if (!sni_host.empty()) {
            SSL_set_tlsext_host_name(ssl, sni_host.c_str());
            if (ctx.client_options().pin_sha256.empty() && !ctx.client_options().insecure)
                SSL_set1_host(ssl, sni_host.c_str());  // проверка имени в сертификате
        }
    }
    auto c = std::unique_ptr<TlsConn>(new TlsConn());
    c->ssl_ = ssl;
    c->ctx_ = &ctx;
    return c;
}

static TlsConn::Io map_error(SSL* ssl, int rc, std::string& err) {
    int e = SSL_get_error(ssl, rc);
    switch (e) {
        case SSL_ERROR_WANT_READ: return TlsConn::Io::WantRead;
        case SSL_ERROR_WANT_WRITE: return TlsConn::Io::WantWrite;
        case SSL_ERROR_ZERO_RETURN: return TlsConn::Io::Closed;
        case SSL_ERROR_SYSCALL:
            if (ERR_peek_error() == 0) {
                ERR_clear_error();
                return TlsConn::Io::Closed;
            }
            err = ssl_errors();
            return TlsConn::Io::Error;
        default:
            err = ssl_errors();
            return TlsConn::Io::Error;
    }
}

TlsConn::Io TlsConn::handshake() {
    SSL* ssl = static_cast<SSL*>(ssl_);
    ERR_clear_error();
    int rc = SSL_do_handshake(ssl);
    if (rc == 1) return Io::Ok;
    Io r = map_error(ssl, rc, err_);
    if (r == Io::Error) {
        long v = SSL_get_verify_result(ssl);
        if (v != X509_V_OK) err_ = std::string("certificate verification failed: ") + X509_verify_cert_error_string(v);
    }
    return r;
}

TlsConn::Io TlsConn::read(char* buf, size_t n, size_t& got) {
    got = 0;
    SSL* ssl = static_cast<SSL*>(ssl_);
    ERR_clear_error();
    int rc = SSL_read(ssl, buf, int(n > (1u << 30) ? (1u << 30) : n));
    if (rc > 0) {
        got = size_t(rc);
        return Io::Ok;
    }
    return map_error(ssl, rc, err_);
}

TlsConn::Io TlsConn::write(const char* buf, size_t n, size_t& wrote) {
    wrote = 0;
    SSL* ssl = static_cast<SSL*>(ssl_);
    ERR_clear_error();
    int rc = SSL_write(ssl, buf, int(n > (1u << 30) ? (1u << 30) : n));
    if (rc > 0) {
        wrote = size_t(rc);
        return Io::Ok;
    }
    return map_error(ssl, rc, err_);
}

void TlsConn::shutdown() {
    if (ssl_) SSL_shutdown(static_cast<SSL*>(ssl_));
}

std::string TlsConn::peer_fingerprint() {
    X509* cert = peer_certificate(static_cast<SSL*>(ssl_));
    if (!cert) return "";
    std::string fp = x509_fingerprint(cert);
    X509_free(cert);
    return fp;
}

bool TlsConn::verify_pin(std::string& error) {
    const std::string& pin = ctx_->client_options().pin_sha256;
    if (pin.empty()) return true;
    std::string fp = peer_fingerprint();
    std::string want = to_lower(pin);
    if (!starts_with(want, "sha256:")) want = "sha256:" + want;
    std::string clean;
    for (char c : want)
        if (c != ':' || clean.size() < 7) clean.push_back(c);  // допускаем двоеточия в hex
    if (fp.empty() || !constant_time_equals(fp, clean)) {
        error = "server certificate fingerprint mismatch: got " + (fp.empty() ? std::string("none") : fp) +
                ", expected " + clean;
        return false;
    }
    return true;
}

bool generate_self_signed(const std::string& cert_file, const std::string& key_file,
                          const std::vector<std::string>& names, int days, std::string& fingerprint,
                          std::string& error) {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        error = "key generation failed: " + ssl_errors();
        EVP_PKEY_CTX_free(kctx);
        return false;
    }
    EVP_PKEY_CTX_free(kctx);

    X509* x = X509_new();
    X509_set_version(x, 2);
    unsigned char serial[16];
    RAND_bytes(serial, sizeof(serial));
    serial[0] &= 0x7F;
    BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), nullptr);
    BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
    BN_free(bn);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), long(days) * 86400L);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    std::string cn = names.empty() ? "sentinel" : names[0];
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("SentinelCore"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(x, name);

    std::string san;
    for (auto& n : names) {
        if (!san.empty()) san += ",";
        bool is_ip = !n.empty() && (is_digit(n[0]) || n.find(':') != std::string::npos);
        san += (is_ip ? "IP:" : "DNS:") + n;
    }
    X509V3_CTX v3;
    X509V3_set_ctx_nodb(&v3);
    X509V3_set_ctx(&v3, x, x, nullptr, nullptr, 0);
    auto add_ext = [&](int nid, const std::string& value) {
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &v3, nid, value.c_str());
        if (!ext) return false;
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
        return true;
    };
    bool ok = add_ext(NID_basic_constraints, "critical,CA:FALSE") &&
              add_ext(NID_key_usage, "critical,digitalSignature,keyEncipherment") &&
              add_ext(NID_ext_key_usage, "serverAuth") && (san.empty() || add_ext(NID_subject_alt_name, san));
    if (!ok || !X509_sign(x, pkey, EVP_sha256())) {
        error = "certificate creation failed: " + ssl_errors();
        X509_free(x);
        EVP_PKEY_free(pkey);
        return false;
    }

    std::error_code ec;
    for (auto* p : {&cert_file, &key_file}) {
        std::filesystem::path dir = std::filesystem::path(*p).parent_path();
        if (!dir.empty()) std::filesystem::create_directories(dir, ec);
    }
    FILE* kf = std::fopen(key_file.c_str(), "wb");
    FILE* cf = kf ? std::fopen(cert_file.c_str(), "wb") : nullptr;
    bool written = kf && cf && PEM_write_PrivateKey(kf, pkey, nullptr, nullptr, 0, nullptr, nullptr) &&
                   PEM_write_X509(cf, x);
    if (kf) std::fclose(kf);
    if (cf) std::fclose(cf);
#ifndef _WIN32
    std::filesystem::permissions(key_file, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
#endif
    fingerprint = x509_fingerprint(x);
    X509_free(x);
    EVP_PKEY_free(pkey);
    if (!written) {
        error = "cannot write " + cert_file + " / " + key_file;
        return false;
    }
    return true;
}

bool cert_file_fingerprint(const std::string& cert_file, std::string& fingerprint, std::string& error) {
    FILE* f = std::fopen(cert_file.c_str(), "rb");
    if (!f) {
        error = "cannot open " + cert_file;
        return false;
    }
    X509* x = PEM_read_X509(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    if (!x) {
        error = "cannot parse certificate " + cert_file;
        return false;
    }
    fingerprint = x509_fingerprint(x);
    X509_free(x);
    return true;
}

#else  // без OpenSSL

static const char* kNoTls = "built without OpenSSL: TLS is unavailable (install OpenSSL and rebuild)";

bool tls_available() { return false; }
std::string tls_library_version() { return "none"; }
TlsContext::~TlsContext() = default;
std::unique_ptr<TlsContext> TlsContext::server(const std::string&, const std::string&, std::string& error) {
    error = kNoTls;
    return nullptr;
}
std::unique_ptr<TlsContext> TlsContext::client(const ClientTlsOptions&, std::string& error) {
    error = kNoTls;
    return nullptr;
}
TlsConn::~TlsConn() = default;
std::unique_ptr<TlsConn> TlsConn::create(TlsContext&, socket_t, const std::string&) { return nullptr; }
TlsConn::Io TlsConn::handshake() { return Io::Error; }
TlsConn::Io TlsConn::read(char*, size_t, size_t& got) {
    got = 0;
    return Io::Error;
}
TlsConn::Io TlsConn::write(const char*, size_t, size_t& wrote) {
    wrote = 0;
    return Io::Error;
}
void TlsConn::shutdown() {}
bool TlsConn::verify_pin(std::string& error) {
    error = kNoTls;
    return false;
}
std::string TlsConn::peer_fingerprint() { return ""; }
bool generate_self_signed(const std::string&, const std::string&, const std::vector<std::string>&, int, std::string&,
                          std::string& error) {
    error = kNoTls;
    return false;
}
bool cert_file_fingerprint(const std::string&, std::string&, std::string& error) {
    error = kNoTls;
    return false;
}

#endif

}  // namespace sentinel::net
