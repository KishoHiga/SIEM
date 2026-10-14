// SentinelCore — шифрование соединений (TLS).
// ЕДИНСТВЕННОЕ место проекта, где используется сторонняя библиотека: системный OpenSSL.
// Остальной код работает только с этим интерфейсом. Без OpenSSL проект тоже собирается,
// тогда функции TLS возвращают понятную ошибку.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "net/socket.hpp"

namespace sentinel::net {

bool tls_available();
std::string tls_library_version();

struct ClientTlsOptions {
    std::string ca_file;     // свой корневой сертификат (иначе — системные)
    std::string pin_sha256;  // закрепление: "sha256:<hex>" отпечаток сертификата сервера
    bool insecure = false;   // НЕ проверять сертификат (только для отладки)
};

class TlsContext {
public:
    ~TlsContext();
    static std::unique_ptr<TlsContext> server(const std::string& cert_file, const std::string& key_file,
                                              std::string& error);
    static std::unique_ptr<TlsContext> client(const ClientTlsOptions& opt, std::string& error);

    bool is_server() const { return server_; }
    const ClientTlsOptions& client_options() const { return copt_; }
    void* native() const { return ctx_; }

private:
    TlsContext() = default;
    void* ctx_ = nullptr;
    bool server_ = false;
    ClientTlsOptions copt_;
};

class TlsConn {
public:
    enum class Io { Ok, WantRead, WantWrite, Closed, Error };

    ~TlsConn();
    static std::unique_ptr<TlsConn> create(TlsContext& ctx, socket_t fd, const std::string& sni_host);

    // Рукопожатие (для неблокирующего сокета вызывать повторно при WantRead/WantWrite).
    Io handshake();
    Io read(char* buf, size_t n, size_t& got);
    Io write(const char* buf, size_t n, size_t& wrote);
    void shutdown();

    // Проверка закреплённого отпечатка (клиент): вызывается после рукопожатия.
    bool verify_pin(std::string& error);
    std::string peer_fingerprint();
    std::string last_error() const { return err_; }

private:
    TlsConn() = default;
    void* ssl_ = nullptr;
    TlsContext* ctx_ = nullptr;
    std::string err_;
};

// Создать самоподписанный сертификат (ECDSA P-256) с именами/адресами в SAN.
// fingerprint = "sha256:<hex>" — его указывают агентам для закрепления.
bool generate_self_signed(const std::string& cert_file, const std::string& key_file,
                          const std::vector<std::string>& names, int days, std::string& fingerprint,
                          std::string& error);
// Отпечаток сертификата из файла.
bool cert_file_fingerprint(const std::string& cert_file, std::string& fingerprint, std::string& error);

}  // namespace sentinel::net
