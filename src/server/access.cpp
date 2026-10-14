#include "server/access.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "core/crypto.hpp"
#include "core/log.hpp"
#include "core/util.hpp"
#include "core/yaml.hpp"

namespace fs = std::filesystem;

namespace sentinel {

static int64_t file_stamp(const std::string& path) {
    std::error_code ec;
    auto t = fs::last_write_time(path, ec);
    if (ec) return -1;
    auto sz = fs::file_size(path, ec);
    return int64_t(t.time_since_epoch().count()) ^ (int64_t(sz) << 1);
}

void KeyStore::init(std::vector<ApiKey> static_keys, std::string file) {
    std::unique_lock<std::shared_mutex> lock(mu_);
    static_keys_ = std::move(static_keys);
    file_ = std::move(file);
    keys_ = static_keys_;
}

bool KeyStore::reload(std::string& error) {
    std::vector<ApiKey> fresh;
    std::string file;
    {
        std::shared_lock<std::shared_mutex> lock(mu_);
        fresh = static_keys_;
        file = file_;
    }
    int64_t stamp = file_stamp(file);
    if (!read_keys_file(file, fresh, error)) return false;
    std::unique_lock<std::shared_mutex> lock(mu_);
    keys_ = std::move(fresh);
    file_stamp_ = stamp;
    return true;
}

void KeyStore::reload_if_changed() {
    int64_t stamp;
    {
        std::shared_lock<std::shared_mutex> lock(mu_);
        stamp = file_stamp(file_);
        if (stamp == file_stamp_) return;
    }
    std::string err;
    if (reload(err)) log::info("keys: reloaded (", size(), " keys)");
    else log::error("keys: reload failed, keeping previous keys: ", err);
}

std::optional<ApiKey> KeyStore::find_by_secret(std::string_view secret) const {
    if (secret.empty() || secret.size() > 256) return std::nullopt;
    std::string hash = sha256_hex(secret);
    std::shared_lock<std::shared_mutex> lock(mu_);
    const ApiKey* found = nullptr;
    for (auto& k : keys_)
        if (constant_time_equals(hash, k.sha256)) found = &k;  // без раннего выхода
    if (!found) return std::nullopt;
    return *found;
}

std::optional<ApiKey> KeyStore::find_by_hash(const std::string& sha256) const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    for (auto& k : keys_)
        if (k.sha256 == sha256) return k;
    return std::nullopt;
}

bool KeyStore::has_name(const std::string& name) const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    for (auto& k : keys_)
        if (k.name == name) return true;
    return false;
}

size_t KeyStore::size() const {
    std::shared_lock<std::shared_mutex> lock(mu_);
    return keys_.size();
}

bool KeyStore::add(const std::string& name, Role role, std::string& secret, std::string& error,
                   const std::string* preset) {
    if (!valid_key_name(name)) {
        error = "bad key name";
        return false;
    }
    std::unique_lock<std::shared_mutex> lock(mu_);
    for (auto& k : keys_)
        if (k.name == name) {
            error = "key '" + name + "' already exists";
            return false;
        }
    if (preset) {
        if (preset->size() < 20 || preset->size() > 200 ||
            preset->find_first_of(" \t\r\n") != std::string::npos) {
            error = "the key must be 20..200 characters without spaces";
            return false;
        }
        secret = *preset;
    } else {
        secret = "snt_" + random_hex(24);
    }
    ApiKey k{name, role, sha256_hex(secret)};
    if (!append_key_file(file_, k, error)) return false;
    keys_.push_back(k);
    file_stamp_ = file_stamp(file_);
    return true;
}

// ---------------- Токены подключения ----------------

bool EnrollStore::load(std::vector<Token>& out, std::string& error) const {
    out.clear();
    std::ifstream in(file_, std::ios::binary);
    if (!in) return true;
    std::stringstream ss;
    ss << in.rdbuf();
    YNode n;
    if (!parse_yaml(ss.str(), n, error)) return false;
    const YNode* list = n.get("tokens");
    if (!list) return true;
    for (auto& t : list->seq) {
        Token tk;
        tk.sha256 = t.str("sha256");
        tk.expires = t.integer("expires").value_or(0);
        tk.uses = int(t.integer("uses").value_or(0));
        tk.label = t.str("label");
        if (tk.sha256.size() == 64) out.push_back(tk);
    }
    return true;
}

bool EnrollStore::save(const std::vector<Token>& tokens, std::string& error) const {
    std::error_code ec;
    fs::path p(file_);
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    std::string tmp = file_ + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            error = "cannot write " + tmp;
            return false;
        }
        out << "# Одноразовые токены подключения агентов (хранятся только хеши).\ntokens:\n";
        for (auto& t : tokens) {
            out << "  - sha256: " << t.sha256 << "\n    expires: " << t.expires << "\n    uses: " << t.uses << "\n";
            if (!t.label.empty()) out << "    label: '" << t.label << "'\n";
        }
    }
#ifndef _WIN32
    fs::permissions(tmp, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec);
#endif
    fs::rename(tmp, file_, ec);
    if (ec) {
        fs::remove(file_, ec);
        fs::rename(tmp, file_, ec);
    }
    if (ec) {
        error = "cannot replace " + file_;
        return false;
    }
    return true;
}

bool EnrollStore::create(int64_t ttl_ms, int uses, const std::string& label, std::string& secret, std::string& error) {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<Token> tokens;
    if (!load(tokens, error)) return false;
    const int64_t now = now_ms();
    std::vector<Token> alive;
    for (auto& t : tokens)
        if (t.expires > now && t.uses > 0) alive.push_back(t);
    secret = "sne_" + random_hex(20);
    std::string clean_label;
    for (char c : label)
        if (c != '\'' && c != '\n' && c != '\r') clean_label.push_back(c);
    alive.push_back({sha256_hex(secret), now + ttl_ms, uses < 1 ? 1 : uses, clean_label});
    return save(alive, error);
}

EnrollStore::Result EnrollStore::consume(std::string_view secret) {
    if (secret.size() < 8 || secret.size() > 128) return Result::Invalid;
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<Token> tokens;
    std::string err;
    if (!load(tokens, err)) return Result::Invalid;
    std::string hash = sha256_hex(secret);
    const int64_t now = now_ms();
    for (auto& t : tokens) {
        if (!constant_time_equals(hash, t.sha256)) continue;
        if (t.expires <= now || t.uses <= 0) return Result::Expired;
        --t.uses;
        std::vector<Token> alive;
        for (auto& x : tokens)
            if (x.expires > now && x.uses > 0) alive.push_back(x);
        if (!save(alive, err)) log::error("enroll: ", err);
        return Result::Ok;
    }
    return Result::Invalid;
}

}  // namespace sentinel
