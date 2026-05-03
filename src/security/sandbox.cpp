#include "chaincpp/security/sandbox.hpp"

#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdlib>

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <processthreadsapi.h>
    #include <memoryapi.h>
#else
    #include <sys/resource.h>
    #include <sys/time.h>
    #include <unistd.h>
    #include <signal.h>
    #include <cstring>
#endif

namespace chaincpp::security {

// ============================================================================
// Platform-Specific Implementations
// ============================================================================

#ifdef _WIN32
class WindowsSandboxImpl {
public:
    static bool set_memory_limit(size_t max_bytes) {
        HANDLE job = CreateJobObject(nullptr, nullptr);
        if (!job) return false;
        
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_JOB_MEMORY;
        limits.JobMemoryLimit = max_bytes;
        
        return SetInformationJobObject(job, 
            JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE;
    }
    
    static void sanitize_environment() {
        // Using _putenv safely or casting to void to ensure no unused results
        (void)_putenv("PATH=");
        (void)_putenv("TEMP=");
        (void)_putenv("TMP=");
    }
};
#endif

#ifdef __unix__
class UnixSandboxImpl {
public:
    static bool set_memory_limit(size_t max_bytes) {
        struct rlimit limit;
        limit.rlim_cur = max_bytes;
        limit.rlim_max = max_bytes;
        return setrlimit(RLIMIT_AS, &limit) == 0;
    }
    
    static bool set_cpu_limit(std::chrono::milliseconds timeout) {
        struct rlimit limit;
        limit.rlim_cur = static_cast<rlim_t>(timeout.count() / 1000);
        limit.rlim_max = static_cast<rlim_t>(timeout.count() / 1000);
        return setrlimit(RLIMIT_CPU, &limit) == 0;
    }
    
    static void sanitize_environment() {
        (void)unsetenv("LD_PRELOAD");
        (void)unsetenv("LD_LIBRARY_PATH");
        (void)unsetenv("BASH_ENV");
    }
};
#endif

// ============================================================================
// Sandbox Implementation
// ============================================================================

Sandbox::~Sandbox() {
    // Virtual destructor implementation
}

bool Sandbox::set_memory_limit(size_t max_bytes) {
#ifdef _WIN32
    return WindowsSandboxImpl::set_memory_limit(max_bytes);
#elif defined(__unix__)
    return UnixSandboxImpl::set_memory_limit(max_bytes);
#else
    (void)max_bytes; // Silence unused warning
    return true;
#endif
}

bool Sandbox::set_time_limit([[maybe_unused]] std::chrono::milliseconds timeout) {
#ifdef __unix__
    return UnixSandboxImpl::set_cpu_limit(timeout);
#else
    // On Windows, the timeout is handled in the execute_safe loop
    // We mark it [[maybe_unused]] in the signature to satisfy -Werror
    return true;
#endif
}

void Sandbox::sanitize_environment() {
#ifdef _WIN32
    WindowsSandboxImpl::sanitize_environment();
#elif defined(__unix__)
    UnixSandboxImpl::sanitize_environment();
#endif
}

bool Sandbox::check_network_allowed(bool allowed) {
    return allowed; 
}

Result<void> Sandbox::execute_safe(
    std::function<Result<void>()> func,
    const SecurityLimits& limits
) {
    if (!set_memory_limit(limits.max_memory_bytes)) {
        return Result<void>::err("Failed to set memory limit");
    }
    
    if (!set_time_limit(limits.timeout)) {
        return Result<void>::err("Failed to set time limit");
    }
    
    sanitize_environment();
    
    std::atomic<bool> completed{false};
    std::string error_msg;
    
    std::thread worker([&]() {
        auto result = func();
        if (result.is_err()) {
            error_msg = result.error();
        }
        completed = true;
    });
    
    auto start = std::chrono::steady_clock::now();
    bool timeout_occurred = false;

    while (!completed) {
        if (std::chrono::steady_clock::now() - start > limits.timeout) {
            timeout_occurred = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    if (timeout_occurred) {
        worker.detach(); // Allow thread to die in background
        return Result<void>::err("Execution timeout exceeded");
    }
    
    if (worker.joinable()) {
        worker.join();
    }
    
    if (!error_msg.empty()) {
        return Result<void>::err(error_msg);
    }
    
    return Result<void>::ok();
}

} // namespace chaincpp::security
