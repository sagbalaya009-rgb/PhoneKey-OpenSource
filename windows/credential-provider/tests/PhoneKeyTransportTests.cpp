#define PHONEKEY_TRANSPORT_TESTING
#include "../PhoneKeyIpc.cpp"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <thread>
#include <utility>

namespace {
    void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
    HRESULT AcceptPeer(HANDLE, HandleGuard&) { return S_OK; }
    HRESULT AcceptRecheck(HANDLE, HANDLE) { return S_OK; }
    HRESULT DenyPeer(HANDLE, HandleGuard&) { return E_ACCESSDENIED; }
    HRESULT DenyRecheck(HANDLE, HANDLE) { return E_ACCESSDENIED; }
    HANDLE stalled = nullptr;
    HANDLE reached = nullptr;
    void HoldCancellation() { SetEvent(reached); WaitForSingleObject(stalled, INFINITE); }
    HRESULT HoldVerification(HANDLE, HandleGuard&) { HoldCancellation(); return S_OK; }

    void DrainWorker()
    {
        if (gExchangeThread.get() != INVALID_HANDLE_VALUE)
            Require(WaitForSingleObject(gExchangeThread.get(), 4000) == WAIT_OBJECT_0, "worker did not drain");
    }
    void ResetTest()
    {
        DrainWorker();
        static unsigned sequence = 0;
        gTestPipeName = L"\\\\.\\pipe\\PhoneKey.TransportTest." + std::to_wstring(GetCurrentProcessId()) +
            L"." + std::to_wstring(GetTickCount64()) + L"." + std::to_wstring(++sequence);
        gTestTimeoutMs = 1000;
        gTestVerifyPeer = AcceptPeer;
        gTestRecheckPeer = AcceptRecheck;
        gTestAfterCancel = nullptr;
    }
    std::vector<std::uint8_t> Response(std::uint8_t state = 6)
    {
        return {'P','K','R','2',2,0,0,0,0,0,0,1,state};
    }

    enum class Behavior { Reply, Silent, Disconnect };
    class Server
    {
    public:
        HandleGuard pipe;
        HandleGuard stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        std::atomic<bool> received{false};
        std::vector<std::uint8_t> request;
        std::thread thread;
        Server(Behavior behavior = Behavior::Reply, std::vector<std::uint8_t> reply = Response(), DWORD buffer = 4096)
            : pipe(CreateNamedPipeW(gTestPipeName.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
                FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE |
                PIPE_REJECT_REMOTE_CLIENTS, 1, buffer, buffer, 1000, nullptr))
        {
            Require(pipe.get() != INVALID_HANDLE_VALUE && stop.get(), "test server creation failed");
            thread = std::thread([this, behavior, reply]() {
                HandleGuard event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
                OVERLAPPED op{}; op.hEvent = event.get();
                if (!ConnectNamedPipe(pipe.get(), &op))
                {
                    DWORD error = GetLastError();
                    if (error != ERROR_PIPE_CONNECTED &&
                        (error != ERROR_IO_PENDING || !WaitOperation(op))) return;
                }
                if (behavior == Behavior::Silent) { WaitForSingleObject(stop.get(), 4000); return; }
                if (behavior == Behavior::Disconnect) { DisconnectNamedPipe(pipe.get()); return; }
                std::array<std::uint8_t, kMaxFrameLength> input{};
                DWORD count = 0;
                ResetEvent(event.get()); op = OVERLAPPED{}; op.hEvent = event.get();
                if (!ReadFile(pipe.get(), input.data(), static_cast<DWORD>(input.size()), &count, &op))
                {
                    if (GetLastError() != ERROR_IO_PENDING || !WaitOperation(op) ||
                        !GetOverlappedResult(pipe.get(), &op, &count, FALSE)) return;
                }
                request.assign(input.begin(), input.begin() + count);
                received.store(true);
                ResetEvent(event.get()); op = OVERLAPPED{}; op.hEvent = event.get();
                if (!WriteFile(pipe.get(), reply.data(), static_cast<DWORD>(reply.size()), &count, &op))
                {
                    if (GetLastError() != ERROR_IO_PENDING || !WaitOperation(op)) return;
                }
                // Keep the pipe connected until the client has consumed the reply.
                const ULONGLONG start = GetTickCount64();
                while (GetTickCount64() - start < 4000 && WaitForSingleObject(stop.get(), 1) == WAIT_TIMEOUT)
                {
                    DWORD available = 0;
                    if (!PeekNamedPipe(pipe.get(), nullptr, 0, nullptr, &available, nullptr)) break;
                }
            });
        }
        ~Server() { SetEvent(stop.get()); if (thread.joinable()) thread.join(); }
        bool WaitOperation(OVERLAPPED& op)
        {
            HANDLE handles[] = {op.hEvent, stop.get()};
            const DWORD result = WaitForMultipleObjects(2, handles, FALSE, 4000);
            if (result == WAIT_OBJECT_0) return true;
            CancelIoEx(pipe.get(), &op);
            DWORD ignored = 0;
            GetOverlappedResult(pipe.get(), &op, &ignored, TRUE);
            return false;
        }
    };

    HRESULT Status(phonekey::CredentialLoginState* state = nullptr)
    {
        phonekey::CredentialLoginState temporary = phonekey::CredentialLoginState::Pending;
        return phonekey::GetCredentialProviderLoginStatus(std::vector<std::uint8_t>(16, 1), state ? state : &temporary);
    }

    void WireAndMalformedFrames()
    {
        Require(static_cast<int>(Command::BeginCredentialProviderLogin) == 11 &&
            static_cast<int>(Command::SubmitCredentialProviderProof) == 12 &&
            static_cast<int>(Command::CancelCredentialProviderLogin) == 13 &&
            static_cast<int>(Command::GetCredentialProviderLoginStatus) == 14 &&
            static_cast<int>(Command::RedeemCredentialProviderPassword) == 17 &&
            static_cast<int>(Command::RedeemCredentialProviderLocalPassword) == 20, "wire IDs changed");
        for (unsigned kind = 0; kind < 7; ++kind)
        {
            auto bytes = Response();
            switch (kind) {
            case 0: bytes[0] = 'X'; break;
            case 1: bytes[4] = 9; break;
            case 2: bytes[6] = 1; break;
            case 3: bytes[5] = 99; break;
            case 4: bytes[11] = 2; break;
            case 5: bytes.resize(5); break;
            default: bytes[8] = 1; break;
            }
            phonekey::ServiceStatus status{}; std::vector<std::uint8_t> payload;
            Require(FAILED(ValidateAndDecodeResponse(bytes.data(), bytes.size(), &status, &payload)), "malformed frame accepted");
        }
    }
    void ServiceIdentityPolicy()
    {
        SERVICE_STATUS_PROCESS s{}; s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        s.dwCurrentState = SERVICE_RUNNING; s.dwProcessId = 123;
        Require(MatchesRunningService(s, 123), "matching service rejected");
        Require(!MatchesRunningService(s, 0) && !MatchesRunningService(s, 124), "wrong PID accepted");
        for (DWORD state : {SERVICE_STOPPED, SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_PAUSED}) {
            s.dwCurrentState = state; Require(!MatchesRunningService(s, 123), "non-running service accepted");
        }
        s.dwCurrentState = SERVICE_RUNNING; s.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
        Require(!MatchesRunningService(s, 123), "shared service process accepted");
        Require(RemainingBudget(GetTickCount64() - 1000, 100) == 0, "deadline underflow");
    }
    void RealVerifierRejectsOrdinaryServer()
    {
        ResetTest(); gTestVerifyPeer = nullptr; gTestRecheckPeer = nullptr;
        Server server;
        Require(FAILED(Status()), "production verifier accepted test process as PhoneKey service");
        DrainWorker(); Require(!server.received.load(), "request was sent before peer authentication");
    }
    void VerifiedResponse()
    {
        ResetTest(); Server server;
        phonekey::CredentialLoginState state = phonekey::CredentialLoginState::Pending;
        Require(SUCCEEDED(Status(&state)) && state == phonekey::CredentialLoginState::Authenticated, "verified reply failed");
        DrainWorker(); Require(server.received.load() && server.request.size() >= kHeaderLength && server.request[5] == 14, "CP sent wrong command");
    }
    void BeginQrExpiryResponse()
    {
        auto makeReply = [](bool validExpiry, std::uint8_t version) {
            std::vector<std::uint8_t> payload(26 + (21 * 21 + 7) / 8, 0);
            payload[0] = version;
            payload[1] = 7;
            payload[17] = 21;
            if (validExpiry) payload[25] = 42;
            auto frame = Response();
            frame.resize(12);
            const auto length = static_cast<std::uint32_t>(payload.size());
            frame[8] = static_cast<std::uint8_t>(length >> 24);
            frame[9] = static_cast<std::uint8_t>(length >> 16);
            frame[10] = static_cast<std::uint8_t>(length >> 8);
            frame[11] = static_cast<std::uint8_t>(length);
            frame.insert(frame.end(), payload.begin(), payload.end());
            return frame;
        };
        for (const auto& sample : {
            std::pair<bool, std::uint8_t>{true, static_cast<std::uint8_t>(2)},
            std::pair<bool, std::uint8_t>{false, static_cast<std::uint8_t>(2)},
            std::pair<bool, std::uint8_t>{true, static_cast<std::uint8_t>(1)}})
        {
            ResetTest();
            Server server(Behavior::Reply, makeReply(sample.first, sample.second));
            phonekey::CredentialLoginBeginResult result;
            const HRESULT hr = phonekey::BeginCredentialProviderLogin(
                L"S-1-5-21-1", phonekey::LoginOperation::Logon, &result);
            if (sample.first && sample.second == 2)
                Require(SUCCEEDED(hr) && result.expiresAtMs == 42 && result.qrWidth == 21 &&
                    result.transactionId.size() == 16 && result.qrBits.size() == 56,
                    "version 2 QR expiry was not parsed");
            else
                Require(FAILED(hr), "invalid QR expiry or version was accepted");
            DrainWorker();
        }
    }
    void InitialPeerRejection()
    {
        ResetTest(); gTestVerifyPeer = DenyPeer; Server server;
        Require(Status() == E_ACCESSDENIED, "initial peer rejection ignored");
        DrainWorker(); Require(!server.received.load(), "request leaked to rejected server");
    }
    void FinalPeerRejection()
    {
        ResetTest(); gTestRecheckPeer = DenyRecheck; Server server;
        std::vector<std::uint8_t> payload{99}; phonekey::ServiceStatus status = phonekey::ServiceStatus::Success;
        HRESULT hr = Exchange(Command::GetCredentialProviderLoginStatus, std::vector<std::uint8_t>(16, 1), &status, &payload);
        Require(hr == E_ACCESSDENIED && payload.empty() && status == phonekey::ServiceStatus::InternalError,
            "unverified response escaped"); DrainWorker();
    }
    void MalformedResponse()
    {
        ResetTest(); auto bad = Response(); bad[0] = 'X'; Server server(Behavior::Reply, bad);
        Require(FAILED(Status()), "malformed wire response accepted"); DrainWorker();
    }
    void OversizedResponse()
    {
        ResetTest(); Server server(Behavior::Reply, std::vector<std::uint8_t>(kMaxFrameLength + 1, 0));
        Require(Status() == HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW), "oversized response accepted"); DrainWorker();
    }
    void UnknownLoginState()
    {
        ResetTest(); Server server(Behavior::Reply, Response(255));
        Require(FAILED(Status()), "unknown login state accepted"); DrainWorker();
    }
    void PasswordResponseNeedsVerifiedPeerAndValidUtf16()
    {
        for (const auto& sample : {
            std::pair<std::vector<std::uint8_t>, bool>{{'P','K','R','2',2,0,0,0,0,0,0,4,'A',0,'B',0}, true},
            std::pair<std::vector<std::uint8_t>, bool>{{'P','K','R','2',2,0,0,0,0,0,0,2,0,0}, false},
            std::pair<std::vector<std::uint8_t>, bool>{{'P','K','R','2',2,0,0,0,0,0,0,1,'A'}, false}
        })
        {
            ResetTest(); Server server(Behavior::Reply, sample.first);
            std::vector<wchar_t> password;
            const HRESULT hr = phonekey::RedeemCredentialProviderPassword(
                std::vector<std::uint8_t>(16, 1), &password);
            Require((SUCCEEDED(hr) == sample.second), "malformed password response accepted");
            if (sample.second)
                Require(server.request.size() >= 6 && server.request[5] == 17 &&
                    password == std::vector<wchar_t>({L'A', L'B', 0}),
                    "verified password response decoded incorrectly");
            if (!password.empty()) SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
            DrainWorker();
        }
    }

    void LocalPasswordUsesSeparateCommand()
    {
        ResetTest();
        Server server(Behavior::Reply,
            {'P','K','R','2',2,0,0,0,0,0,0,2,'A',0});
        std::vector<wchar_t> password;
        phonekey::ServiceStatus status = phonekey::ServiceStatus::InternalError;
        const HRESULT hr = phonekey::RedeemCredentialProviderPassword(
            std::vector<std::uint8_t>(16, 1), &password, &status, true);
        DrainWorker();
        Require(SUCCEEDED(hr) && status == phonekey::ServiceStatus::Success &&
            password.size() == 2 && password[0] == L'A' && password[1] == 0 &&
            server.received.load() && server.request.size() >= kHeaderLength &&
            server.request[5] == 20, "local password used wrong command");
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    }
    void DisconnectFailsClosed()
    {
        ResetTest(); Server server(Behavior::Disconnect);
        Require(FAILED(Status()), "disconnect succeeded"); DrainWorker();
    }
    void AbsentServer()
    {
        ResetTest(); const ULONGLONG start = GetTickCount64();
        Require(FAILED(Status()), "missing server succeeded");
        Require(GetTickCount64() - start < 1500, "missing pipe call blocked"); DrainWorker();
    }
    void ReadDeadline()
    {
        ResetTest(); gTestTimeoutMs = 150; Server server(Behavior::Silent);
        const ULONGLONG start = GetTickCount64();
        Require(Status() == HRESULT_FROM_WIN32(ERROR_TIMEOUT), "silent peer did not time out");
        Require(GetTickCount64() - start < 1200, "caller exceeded deadline tolerance"); DrainWorker();
    }
    void CancellationDrainDoesNotBlockCaller()
    {
        ResetTest(); gTestTimeoutMs = 150;
        HandleGuard entered(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        HandleGuard release(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        reached = entered.get(); stalled = release.get(); gTestAfterCancel = HoldCancellation;
        Server server(Behavior::Silent);
        const ULONGLONG start = GetTickCount64();
        HRESULT first = Status();
        bool bounded = GetTickCount64() - start < 1200;
        bool paused = WaitForSingleObject(entered.get(), 2000) == WAIT_OBJECT_0;
        const ULONGLONG nextStart = GetTickCount64(); HRESULT next = Status();
        bool immediate = GetTickCount64() - nextStart < 500;
        bool retained = WaitForSingleObject(gExchangeThread.get(), 0) == WAIT_TIMEOUT;
        SetEvent(release.get()); DrainWorker();
        Require(first == HRESULT_FROM_WIN32(ERROR_TIMEOUT) && bounded && paused && retained,
            "caller waited for cancellation drain or lost worker ownership");
        Require(next == HRESULT_FROM_WIN32(ERROR_BUSY) && immediate, "stalled worker allowed unbounded queue growth");
    }
    void SlowVerificationCannotSendLateRequest()
    {
        ResetTest(); gTestTimeoutMs = 150;
        HandleGuard entered(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        HandleGuard release(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        reached = entered.get(); stalled = release.get(); gTestVerifyPeer = HoldVerification;
        Server server;
        const ULONGLONG start = GetTickCount64(); HRESULT result = Status();
        bool bounded = GetTickCount64() - start < 1200;
        bool paused = WaitForSingleObject(entered.get(), 2000) == WAIT_OBJECT_0;
        HRESULT second = Status(); SetEvent(release.get()); DrainWorker();
        Require(result == HRESULT_FROM_WIN32(ERROR_TIMEOUT) && bounded && paused,
            "slow verification blocked caller");
        Require(second == HRESULT_FROM_WIN32(ERROR_BUSY) && !server.received.load(), "late request or additional worker escaped");
    }
    void PendingWriteDeadline()
    {
        ResetTest(); Server server(Behavior::Silent, {}, 1);
        HandleGuard pipe(CreateFileW(gTestPipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
        Require(pipe.get() != INVALID_HANDLE_VALUE, "write test connect failed");
        ExchangeJob job; job.budget = 150;
        std::vector<std::uint8_t> bytes(1024 * 1024, 0);
        DWORD count = 0; const ULONGLONG start = GetTickCount64();
        HRESULT hr = Transfer(pipe.get(), bytes.data(), static_cast<DWORD>(bytes.size()), true, job, &count);
        Require(hr == HRESULT_FROM_WIN32(ERROR_TIMEOUT), "pending write did not time out");
        Require(GetTickCount64() - start < 1200, "pending write did not cancel promptly on local test pipe");
    }
    void RepeatedCallsReleaseHandles()
    {
        VerifiedResponse(); DWORD before = 0; Require(GetProcessHandleCount(GetCurrentProcess(), &before) != FALSE, "handle count failed");
        for (unsigned i = 0; i < 32; ++i) VerifiedResponse();
        DWORD after = 0; Require(GetProcessHandleCount(GetCurrentProcess(), &after) != FALSE, "handle count failed");
        Require(after <= before + 4, "repeated exchanges leak handles");
    }
    void DllRemainsLoadedUntilWorkerExit()
    {
        DrainWorker();
        wchar_t path[32768]{};
        DWORD size = GetModuleFileNameW(nullptr, path, 32768);
        Require(size != 0 && size < 32768, "test path unavailable");
        std::wstring dllPath(path); dllPath.resize(dllPath.find_last_of(L"\\/") + 1);
        dllPath += L"PhoneKeyTransportLifetimeFixture.dll";
        HMODULE module = LoadLibraryW(dllPath.c_str()); Require(module != nullptr, "lifetime fixture DLL failed to load");
        typedef HRESULT (__cdecl *Probe)(const wchar_t*, HANDLE, HANDLE);
        Probe probe = nullptr;
        FARPROC address = GetProcAddress(module, "RunLifetimeProbe");
        static_assert(sizeof(probe) == sizeof(address), "Windows function pointer size mismatch");
        std::memcpy(&probe, &address, sizeof(probe));
        Require(probe != nullptr, "fixture export missing");
        ResetTest(); Server server;
        HandleGuard entered(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        HandleGuard release(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        HRESULT hr = probe(gTestPipeName.c_str(), entered.get(), release.get());
        bool paused = WaitForSingleObject(entered.get(), 2000) == WAIT_OBJECT_0;
        FreeLibrary(module);
        bool pinned = GetModuleHandleW(dllPath.c_str()) != nullptr;
        SetEvent(release.get());
        const ULONGLONG start = GetTickCount64();
        while (GetModuleHandleW(dllPath.c_str()) && GetTickCount64() - start < 4000) Sleep(1);
        bool unloaded = GetModuleHandleW(dllPath.c_str()) == nullptr;
        Require(hr == HRESULT_FROM_WIN32(ERROR_TIMEOUT) && paused && pinned && unloaded,
            "DLL lifetime was not held through worker exit");
        Require(!server.received.load(), "timed-out fixture sent a late request");
    }
}
int main(int argc, char** argv)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc == 3 && std::strcmp(argv[1], "--live-pipe") == 0)
    {
        HandleGuard probe(CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT |
            SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY, nullptr));
        std::printf("PIPE_OPEN=%lu\n", probe.get() == INVALID_HANDLE_VALUE ? GetLastError() : 0);
        if (probe.get() != INVALID_HANDLE_VALUE)
        {
            ULONG pid = 0;
            const BOOL pidOk = GetNamedPipeServerProcessId(probe.get(), &pid);
            std::printf("PIPE_PID_ERROR=%lu PID=%lu\n", pidOk ? 0 : GetLastError(), pid);
            PSID owner = nullptr;
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            const DWORD ownerError = GetSecurityInfo(probe.get(), SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr,
                &descriptor);
            std::printf("PIPE_OWNER_ERROR=%lu PRIVILEGED=%d\n", ownerError,
                ownerError == 0 && owner &&
                (IsWellKnownSid(owner, WinLocalSystemSid) ||
                 IsWellKnownSid(owner, WinBuiltinAdministratorsSid)));
            if (descriptor) LocalFree(descriptor);
            std::printf("SCM_BINDING=0x%08lX\n",
                static_cast<unsigned long>(CheckServiceBinding(probe.get(), nullptr)));
            HandleGuard heldProcess;
            std::printf("VERIFY_PEER=0x%08lX\n",
                static_cast<unsigned long>(VerifyServicePeer(probe.get(), heldProcess)));
            DWORD mode = PIPE_READMODE_MESSAGE;
            const BOOL modeOk = SetNamedPipeHandleState(probe.get(), &mode, nullptr, nullptr);
            std::printf("PIPE_READ_MODE_ERROR=%lu\n", modeOk ? 0 : GetLastError());
        }
        gTestPipeName = kPipeName;
        gTestVerifyPeer = nullptr;
        gTestRecheckPeer = nullptr;
        gTestTimeoutMs = 10000;
        const std::string sidText(argv[2]);
        const std::wstring sid(sidText.begin(), sidText.end());
        phonekey::CredentialLoginBeginResult result;
        phonekey::ServiceStatus status = phonekey::ServiceStatus::InternalError;
        const HRESULT hr = phonekey::BeginCredentialProviderLogin(
            sid, phonekey::LoginOperation::Unlock, &result, &status);
        std::printf("LIVE_PIPE_HRESULT=0x%08lX STATUS=%u QR_WIDTH=%u\n",
            static_cast<unsigned long>(hr), static_cast<unsigned>(status),
            static_cast<unsigned>(result.qrWidth));
        if (SUCCEEDED(hr) && status == phonekey::ServiceStatus::Success)
            phonekey::CancelCredentialProviderLogin(result.transactionId);
        return SUCCEEDED(hr) && status == phonekey::ServiceStatus::Success ? 0 : 1;
    }
    struct Test { const char* name; void (*run)(); };
    const Test tests[] = {
        {"wire IDs and malformed frame rejection", WireAndMalformedFrames},
        {"SCM PID/state policy and monotonic expiry", ServiceIdentityPolicy},
        {"production verifier rejects ordinary fake endpoint", RealVerifierRejectsOrdinaryServer},
        {"verified status response and command 14", VerifiedResponse},
        {"versioned QR expiry response", BeginQrExpiryResponse},
        {"initial peer rejection before writing", InitialPeerRejection},
        {"peer recheck before publishing response", FinalPeerRejection},
        {"malformed response fails closed", MalformedResponse},
        {"oversized response fails closed", OversizedResponse},
        {"unknown login state fails closed", UnknownLoginState},
        {"single-use password response validation", PasswordResponseNeedsVerifiedPeerAndValidUtf16},
        {"local password selects separate service command", LocalPasswordUsesSeparateCommand},
        {"disconnect fails closed", DisconnectFailsClosed},
        {"absent endpoint returns promptly", AbsentServer},
        {"read deadline", ReadDeadline},
        {"cancellation drain is isolated and admission stays bounded", CancellationDrainDoesNotBlockCaller},
        {"slow peer verification cannot publish late work", SlowVerificationCannotSendLateRequest},
        {"pending write deadline", PendingWriteDeadline},
        {"repeated calls release handles", RepeatedCallsReleaseHandles},
        {"DLL stays loaded until timed-out worker exits", DllRemainsLoadedUntilWorkerExit},
    };
    for (const auto& test : tests) {
        try { test.run(); std::printf("PASS: %s\n", test.name); std::fflush(stdout); }
        catch (const std::exception& error) { std::fprintf(stderr, "FAIL: %s: %s\n", test.name, error.what()); return 1; }
    }
    std::puts("PASS: 20 CP transport tests. No service installation or credential serialization performed.");
    return 0;
}
