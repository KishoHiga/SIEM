#include "agent/process.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>

#include "core/util.hpp"

#ifdef _WIN32
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace sentinel::agent {

bool find_executable(const std::string& name, std::string& path) {
    if (name.find('/') != std::string::npos || name.find('\\') != std::string::npos) {
        std::error_code ec;
        if (fs::exists(name, ec)) {
            path = name;
            return true;
        }
        return false;
    }
    std::vector<std::string> dirs;
    if (const char* p = std::getenv("PATH")) {
#ifdef _WIN32
        for (auto d : split(p, ';')) dirs.emplace_back(d);
#else
        for (auto d : split(p, ':')) dirs.emplace_back(d);
#endif
    }
#ifndef _WIN32
    for (const char* d : {"/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"})
        dirs.emplace_back(d);
#endif
    for (auto& d : dirs) {
        if (d.empty()) continue;
        std::error_code ec;
        fs::path cand = fs::path(d) / name;
#ifdef _WIN32
        if (!cand.has_extension()) cand += ".exe";
#endif
        if (fs::is_regular_file(cand, ec)) {
            path = cand.string();
            return true;
        }
    }
    return false;
}

#ifdef _WIN32

static std::string quote_arg(const std::string& a) {
    if (!a.empty() && a.find_first_of(" \t\"") == std::string::npos) return a;
    std::string out = "\"";
    for (char c : a) {
        if (c == '"') out += "\\\"";
        else out.push_back(c);
    }
    return out + "\"";
}

ProcResult run_process(const std::vector<std::string>& argv, const std::string& stdin_data, int timeout_ms) {
    ProcResult r;
    if (argv.empty()) return r;
    std::string cmd;
    for (auto& a : argv) cmd += (cmd.empty() ? "" : " ") + quote_arg(a);
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE out_r = nullptr, out_w = nullptr, in_r = nullptr, in_w = nullptr;
    if (!CreatePipe(&out_r, &out_w, &sa, 0) || !CreatePipe(&in_r, &in_w, &sa, 0)) return r;
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    si.hStdInput = in_r;
    PROCESS_INFORMATION pi{};
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');
    BOOL ok = CreateProcessA(nullptr, buf.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(out_w);
    CloseHandle(in_r);
    if (!ok) {
        CloseHandle(out_r);
        CloseHandle(in_w);
        return r;
    }
    r.started = true;
    DWORD wrote = 0;
    if (!stdin_data.empty()) WriteFile(in_w, stdin_data.data(), DWORD(stdin_data.size()), &wrote, nullptr);
    CloseHandle(in_w);
    char tmp[4096];
    DWORD got = 0;
    auto t0 = std::chrono::steady_clock::now();
    while (true) {
        DWORD avail = 0;
        if (PeekNamedPipe(out_r, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
            if (ReadFile(out_r, tmp, sizeof(tmp), &got, nullptr) && got > 0) r.output.append(tmp, got);
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0) {
            while (ReadFile(out_r, tmp, sizeof(tmp), &got, nullptr) && got > 0) r.output.append(tmp, got);
            break;
        }
        if (std::chrono::steady_clock::now() - t0 > std::chrono::milliseconds(timeout_ms)) {
            TerminateProcess(pi.hProcess, 1);
            r.timed_out = true;
            break;
        }
    }
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    r.exit_code = int(code);
    CloseHandle(out_r);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return r;
}

#else

ProcResult run_process(const std::vector<std::string>& argv, const std::string& stdin_data, int timeout_ms) {
    ProcResult r;
    if (argv.empty()) return r;
    std::signal(SIGPIPE, SIG_IGN);  // программа может закрыть stdin раньше, чем мы всё запишем
    int in_p[2], out_p[2];
    if (pipe(in_p) != 0) return r;
    if (pipe(out_p) != 0) {
        ::close(in_p[0]);
        ::close(in_p[1]);
        return r;
    }
    std::vector<char*> args;
    for (auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(in_p[0], 0);
        dup2(out_p[1], 1);
        dup2(out_p[1], 2);
        ::close(in_p[0]);
        ::close(in_p[1]);
        ::close(out_p[0]);
        ::close(out_p[1]);
        execvp(args[0], args.data());
        _exit(127);
    }
    ::close(in_p[0]);
    ::close(out_p[1]);
    if (pid < 0) {
        ::close(in_p[1]);
        ::close(out_p[0]);
        return r;
    }
    r.started = true;
    fcntl(in_p[1], F_SETFL, fcntl(in_p[1], F_GETFL) | O_NONBLOCK);
    size_t written = 0;
    bool in_open = true;
    if (stdin_data.empty()) {
        ::close(in_p[1]);
        in_open = false;
    }
    auto t0 = std::chrono::steady_clock::now();
    char tmp[4096];
    bool out_open = true;
    while (out_open) {
        pollfd fds[2];
        int n = 0;
        fds[n++] = {out_p[0], POLLIN, 0};
        if (in_open) fds[n++] = {in_p[1], POLLOUT, 0};
        int left = timeout_ms - int(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count());
        if (left <= 0) {
            r.timed_out = true;
            kill(pid, SIGKILL);
            break;
        }
        int rc = poll(fds, nfds_t(n), left);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) continue;
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t k = ::read(out_p[0], tmp, sizeof(tmp));
            if (k > 0) {
                if (r.output.size() < (1u << 20)) r.output.append(tmp, size_t(k));
            } else if (k == 0 || errno != EINTR) {
                out_open = false;
            }
        }
        if (in_open && n > 1 && (fds[1].revents & (POLLOUT | POLLERR | POLLHUP))) {
            ssize_t k = ::write(in_p[1], stdin_data.data() + written, stdin_data.size() - written);
            if (k > 0) written += size_t(k);
            if (k < 0 && errno != EAGAIN && errno != EINTR) written = stdin_data.size();
            if (written >= stdin_data.size()) {
                ::close(in_p[1]);
                in_open = false;
            }
        }
    }
    if (in_open) ::close(in_p[1]);
    ::close(out_p[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) r.exit_code = WEXITSTATUS(status);
    if (r.exit_code == 127 && r.output.empty()) r.output = "cannot run " + argv[0];
    return r;
}

#endif

}  // namespace sentinel::agent
