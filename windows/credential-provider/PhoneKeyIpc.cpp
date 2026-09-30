#include "PhoneKeyIpc.h"

#include <array>
#include <limits>
#include <atomic>
#include <memory>
#include <new>
#include <cerrno>
#include <process.h>
#include <aclapi.h>

#ifdef _MSC_VER
#pragma comment(lib, "Advapi32.lib")
#endif

namespace
{
    constexpr wchar_t kPipeName[] =
        L"\\\\.\\pipe\\PhoneKey.Control.v2";

    constexpr std::uint8_t kIpcVersion = 2;

    constexpr std::size_t kHeaderLength = 12;
    constexpr std::size_t kMaxPayload = 2048;
    constexpr std::size_t kMaxFrameLength =
        kHeaderLength + kMaxPayload;


    constexpr std::array<std::uint8_t, 4> kRequestMagic =
    {
        'P', 'K', 'I', '2'
    };

    constexpr std::array<std::uint8_t, 4> kResponseMagic =
    {
        'P', 'K', 'R', '2'
    };

    enum class Command : std::uint8_t
    {
        BeginCredentialProviderLogin = 11,
        SubmitCredentialProviderProof = 12,
        CancelCredentialProviderLogin = 13,
        GetCredentialProviderLoginStatus = 14,
        RedeemCredentialProviderPassword = 17,
        RedeemCredentialProviderLocalPassword = 20,
    };

    class HandleGuard
    {
    public:
        explicit HandleGuard(HANDLE handle = INVALID_HANDLE_VALUE)
            : _handle(handle)
        {
        }

        ~HandleGuard() { reset(); }

        void reset(HANDLE handle = INVALID_HANDLE_VALUE)
        {
            if (_handle != INVALID_HANDLE_VALUE && _handle != nullptr)
                CloseHandle(_handle);
            _handle = handle;
        }

        HandleGuard(const HandleGuard&) = delete;
        HandleGuard& operator=(const HandleGuard&) = delete;

        HANDLE get() const
        {
            return _handle;
        }

    private:
        HANDLE _handle;
    };

    void AppendU16BigEndian(
        std::vector<std::uint8_t>& output,
        std::uint16_t value)
    {
        output.push_back(
            static_cast<std::uint8_t>((value >> 8) & 0xFF));

        output.push_back(
            static_cast<std::uint8_t>(value & 0xFF));
    }

    void AppendU32BigEndian(
        std::vector<std::uint8_t>& output,
        std::uint32_t value)
    {
        output.push_back(
            static_cast<std::uint8_t>((value >> 24) & 0xFF));

        output.push_back(
            static_cast<std::uint8_t>((value >> 16) & 0xFF));

        output.push_back(
            static_cast<std::uint8_t>((value >> 8) & 0xFF));

        output.push_back(
            static_cast<std::uint8_t>(value & 0xFF));
    }

    std::uint32_t ReadU32BigEndian(
        const std::uint8_t* bytes)
    {
        return
            (static_cast<std::uint32_t>(bytes[0]) << 24) |
            (static_cast<std::uint32_t>(bytes[1]) << 16) |
            (static_cast<std::uint32_t>(bytes[2]) << 8) |
            static_cast<std::uint32_t>(bytes[3]);
    }

    HRESULT SidToAscii(
        const std::wstring& sid,
        std::vector<std::uint8_t>* ascii)
    {
        if (ascii == nullptr)
        {
            return E_POINTER;
        }

        ascii->clear();

        if (sid.empty() ||
            sid.size() > 184 ||
            sid.size() < 3 ||
            sid[0] != L'S' ||
            sid[1] != L'-')
        {
            return E_INVALIDARG;
        }

        ascii->reserve(sid.size());

        for (wchar_t character : sid)
        {
            if (character > 0x7F)
            {
                ascii->clear();
                return E_INVALIDARG;
            }

            ascii->push_back(
                static_cast<std::uint8_t>(character));
        }

        return S_OK;
    }

    HRESULT EncodeSid(
        const std::wstring& sid,
        std::vector<std::uint8_t>* output)
    {
        if (output == nullptr)
        {
            return E_POINTER;
        }

        std::vector<std::uint8_t> asciiSid;

        HRESULT hr = SidToAscii(sid, &asciiSid);

        if (FAILED(hr))
        {
            return hr;
        }

        if (asciiSid.size() >
            std::numeric_limits<std::uint16_t>::max())
        {
            return E_INVALIDARG;
        }

        AppendU16BigEndian(
            *output,
            static_cast<std::uint16_t>(
                asciiSid.size()));

        output->insert(
            output->end(),
            asciiSid.begin(),
            asciiSid.end());

        return S_OK;
    }

    HRESULT BuildRequestFrame(
        Command command,
        const std::vector<std::uint8_t>& payload,
        std::vector<std::uint8_t>* frame)
    {
        if (frame == nullptr)
        {
            return E_POINTER;
        }

        if (payload.size() > kMaxPayload)
        {
            return HRESULT_FROM_WIN32(
                ERROR_BUFFER_OVERFLOW);
        }

        frame->clear();
        frame->reserve(
            kHeaderLength + payload.size());

        frame->insert(
            frame->end(),
            kRequestMagic.begin(),
            kRequestMagic.end());

        frame->push_back(kIpcVersion);
        frame->push_back(
            static_cast<std::uint8_t>(command));

        // Reserved bytes.
        frame->push_back(0);
        frame->push_back(0);

        AppendU32BigEndian(
            *frame,
            static_cast<std::uint32_t>(
                payload.size()));

        frame->insert(
            frame->end(),
            payload.begin(),
            payload.end());

        return S_OK;
    }

    HRESULT StatusToHresult(
        phonekey::ServiceStatus status)
    {
        switch (status)
        {
        case phonekey::ServiceStatus::Success:
            return S_OK;

        case phonekey::ServiceStatus::BadRequest:
            return E_INVALIDARG;

        case phonekey::ServiceStatus::Unauthorized:
            return HRESULT_FROM_WIN32(
                ERROR_ACCESS_DENIED);

        case phonekey::ServiceStatus::Conflict:
            return HRESULT_FROM_WIN32(
                ERROR_BUSY);

        case phonekey::ServiceStatus::Expired:
            return HRESULT_FROM_WIN32(
                ERROR_TIMEOUT);

        case phonekey::ServiceStatus::CryptographicRejection:
            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);

        case phonekey::ServiceStatus::InternalError:
        default:
            return E_FAIL;
        }
    }

    HRESULT ValidateAndDecodeResponse(
        const std::uint8_t* bytes,
        std::size_t length,
        phonekey::ServiceStatus* status,
        std::vector<std::uint8_t>* payload)
    {
        if (bytes == nullptr ||
            status == nullptr ||
            payload == nullptr)
        {
            return E_POINTER;
        }

        if (length < kHeaderLength)
        {
            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        for (std::size_t i = 0;
             i < kResponseMagic.size();
             ++i)
        {
            if (bytes[i] != kResponseMagic[i])
            {
                return HRESULT_FROM_WIN32(
                    ERROR_INVALID_DATA);
            }
        }

        if (bytes[4] != kIpcVersion)
        {
            return HRESULT_FROM_WIN32(
                ERROR_REVISION_MISMATCH);
        }

        if (bytes[6] != 0 ||
            bytes[7] != 0)
        {
            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        const std::uint32_t payloadLength =
            ReadU32BigEndian(bytes + 8);

        if (payloadLength > kMaxPayload)
        {
            return HRESULT_FROM_WIN32(
                ERROR_BUFFER_OVERFLOW);
        }

        const std::size_t expectedLength =
            kHeaderLength +
            static_cast<std::size_t>(
                payloadLength);

        if (length != expectedLength)
        {
            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        switch (bytes[5])
        {
        case 0:
            *status =
                phonekey::ServiceStatus::Success;
            break;

        case 1:
            *status =
                phonekey::ServiceStatus::BadRequest;
            break;

        case 2:
            *status =
                phonekey::ServiceStatus::Unauthorized;
            break;

        case 3:
            *status =
                phonekey::ServiceStatus::Conflict;
            break;

        case 4:
            *status =
                phonekey::ServiceStatus::Expired;
            break;

        case 5:
            *status =
                phonekey::ServiceStatus::
                    CryptographicRejection;
            break;

        case 255:
            *status =
                phonekey::ServiceStatus::
                    InternalError;
            break;

        default:
            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        payload->assign(
            bytes + kHeaderLength,
            bytes + expectedLength);

        return S_OK;
    }

    // One monotonic budget covers connect, peer verification, write and read.
    // The CP caller never waits for cancellation drainage or a stalled SCM RPC.
    constexpr DWORD kExchangeTimeoutMs = 3000;
    SRWLOCK gExchangeLock = SRWLOCK_INIT;
    HandleGuard gExchangeThread;

    struct ExchangeLock
    {
        bool acquired = TryAcquireSRWLockExclusive(&gExchangeLock) != FALSE;
        ~ExchangeLock() { if (acquired) ReleaseSRWLockExclusive(&gExchangeLock); }
    };

    class ServiceHandleGuard
    {
    public:
        explicit ServiceHandleGuard(SC_HANDLE value) : handle(value) {}
        ~ServiceHandleGuard() { if (handle) CloseServiceHandle(handle); }
        ServiceHandleGuard(const ServiceHandleGuard&) = delete;
        ServiceHandleGuard& operator=(const ServiceHandleGuard&) = delete;
        SC_HANDLE handle;
    };

    DWORD RemainingBudget(ULONGLONG started, DWORD budget)
    {
        const ULONGLONG elapsed = GetTickCount64() - started;
        return elapsed >= budget ? 0 : budget - static_cast<DWORD>(elapsed);
    }

    bool MatchesRunningService(const SERVICE_STATUS_PROCESS& status, DWORD pid)
    {
        // SCM does not provide a reliable PID in every pending/stopped state.
        return pid != 0 && status.dwProcessId == pid &&
            status.dwCurrentState == SERVICE_RUNNING &&
            status.dwServiceType == SERVICE_WIN32_OWN_PROCESS;
    }

    HRESULT CheckServiceBinding(HANDLE pipe, HANDLE process)
    {
        ULONG pipePid = 0;
        if (!GetNamedPipeServerProcessId(pipe, &pipePid))
            return HRESULT_FROM_WIN32(GetLastError());
        if (process != nullptr && process != INVALID_HANDLE_VALUE &&
            (WaitForSingleObject(process, 0) != WAIT_TIMEOUT ||
             GetProcessId(process) != pipePid))
            return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);

        ServiceHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm.handle) return HRESULT_FROM_WIN32(GetLastError());
        ServiceHandleGuard service(OpenServiceW(scm.handle, L"PhoneKeyService", SERVICE_QUERY_STATUS));
        if (!service.handle) return HRESULT_FROM_WIN32(GetLastError());
        SERVICE_STATUS_PROCESS status{};
        DWORD required = 0;
        if (!QueryServiceStatusEx(service.handle, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status), sizeof(status), &required))
            return HRESULT_FROM_WIN32(GetLastError());
        return MatchesRunningService(status, pipePid) ? S_OK : HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    }

    HRESULT VerifyServicePeer(HANDLE pipe, HandleGuard& process)
    {
        ULONG pid = 0;
        if (!GetNamedPipeServerProcessId(pipe, &pid))
            return HRESULT_FROM_WIN32(GetLastError());
        if (pid == 0) return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        // A protected service process need not grant LogonUI a process
        // handle. The stable pipe PID is checked against SCM both here and
        // after reading the response.
        // LogonUI may not be allowed to open the service process token.
        // Authenticate the pipe owner's privileged SID instead, then bind
        // the connection to the running service PID below.
        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        const DWORD securityError = GetSecurityInfo(pipe, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr,
            &descriptor);
        if (securityError != ERROR_SUCCESS)
            return HRESULT_FROM_WIN32(securityError);
        const bool privilegedOwner = owner != nullptr &&
            (IsWellKnownSid(owner, WinLocalSystemSid) ||
             IsWellKnownSid(owner, WinBuiltinAdministratorsSid));
        if (descriptor != nullptr) LocalFree(descriptor);
        if (!privilegedOwner) return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
        // Recheck the still-running service PID before accepting any reply.
        return CheckServiceBinding(pipe, process.get());
    }

#ifdef PHONEKEY_TRANSPORT_TESTING
    // Compiled only into the standalone test executable, never the CP DLL.
    std::wstring gTestPipeName;
    DWORD gTestTimeoutMs = kExchangeTimeoutMs;
    HRESULT (*gTestVerifyPeer)(HANDLE, HandleGuard&) = nullptr;
    HRESULT (*gTestRecheckPeer)(HANDLE, HANDLE) = nullptr;
    void (*gTestAfterCancel)() = nullptr;
#endif

    struct ExchangeJob
    {
        std::atomic<unsigned> references{1};
        std::atomic<bool> cancelled{false};
        HandleGuard complete{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        ULONGLONG started = GetTickCount64();
        DWORD budget = kExchangeTimeoutMs;
        std::vector<std::uint8_t> request;
        std::vector<std::uint8_t> response;
        phonekey::ServiceStatus status = phonekey::ServiceStatus::InternalError;
        HRESULT result = E_FAIL;
        ~ExchangeJob()
        {
            if (!request.empty()) SecureZeroMemory(request.data(), request.size());
            if (!response.empty()) SecureZeroMemory(response.data(), response.size());
        }
#ifdef PHONEKEY_TRANSPORT_TESTING
        std::wstring pipeName = gTestPipeName;
        HRESULT (*verifyPeer)(HANDLE, HandleGuard&) = gTestVerifyPeer;
        HRESULT (*recheckPeer)(HANDLE, HANDLE) = gTestRecheckPeer;
        void (*afterCancel)() = gTestAfterCancel;
#endif
        void Release()
        {
            if (references.fetch_sub(1, std::memory_order_acq_rel) == 1) delete this;
        }
        DWORD Remaining() const
        {
            return cancelled.load(std::memory_order_acquire) ? 0 : RemainingBudget(started, budget);
        }
    };
    struct JobRelease { void operator()(ExchangeJob* job) const { job->Release(); } };

    HRESULT Transfer(HANDLE pipe, void* buffer, DWORD length, bool writing,
        ExchangeJob& job, DWORD* transferred)
    {
        if (!job.Remaining()) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        HandleGuard event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event.get()) return HRESULT_FROM_WIN32(GetLastError());
        OVERLAPPED operation{};
        operation.hEvent = event.get();
        *transferred = 0;
        const BOOL immediate = writing
            ? WriteFile(pipe, buffer, length, transferred, &operation)
            : ReadFile(pipe, buffer, length, transferred, &operation);
        if (immediate) return S_OK;
        const DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) return HRESULT_FROM_WIN32(error);
        const DWORD wait = WaitForSingleObject(event.get(), job.Remaining());
        if (wait == WAIT_OBJECT_0)
            return GetOverlappedResult(pipe, &operation, transferred, FALSE)
                ? S_OK : HRESULT_FROM_WIN32(GetLastError());

        const DWORD failure = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        CancelIoEx(pipe, &operation);
#ifdef PHONEKEY_TRANSPORT_TESTING
        if (job.afterCancel) job.afterCancel();
#endif
        // CancelIoEx is a request, not completion. Keep OVERLAPPED, buffer, event
        // and pipe alive until completion. This wait is on the single worker,
        // NEVER on LogonUI. If Windows stalls here, later requests fail busy.
        GetOverlappedResult(pipe, &operation, transferred, TRUE);
        return HRESULT_FROM_WIN32(failure);
    }

    HRESULT ExchangeOnWorker(ExchangeJob& job)
    {
        const wchar_t* pipeName = kPipeName;
#ifdef PHONEKEY_TRANSPORT_TESTING
        pipeName = job.pipeName.c_str();
#endif
        HANDLE rawPipe = INVALID_HANDLE_VALUE;
        while (job.Remaining())
        {
            rawPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT |
                SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY, nullptr);
            if (rawPipe != INVALID_HANDLE_VALUE) break;
            const DWORD error = GetLastError();
            if (error != ERROR_PIPE_BUSY) return HRESULT_FROM_WIN32(error);
            const DWORD remaining = job.Remaining();
            if (!remaining) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
            if (!WaitNamedPipeW(pipeName, remaining))
            {
                const DWORD waitError = GetLastError();
                return HRESULT_FROM_WIN32(waitError == ERROR_SEM_TIMEOUT ? ERROR_TIMEOUT : waitError);
            }
        }
        if (rawPipe == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        HandleGuard pipe(rawPipe);
        if (!job.Remaining()) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        HandleGuard process;
        HRESULT hr;
#ifdef PHONEKEY_TRANSPORT_TESTING
        hr = job.verifyPeer ? job.verifyPeer(pipe.get(), process) : VerifyServicePeer(pipe.get(), process);
#else
        hr = VerifyServicePeer(pipe.get(), process);
#endif
        if (FAILED(hr)) return hr;
        if (!job.Remaining()) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        DWORD readMode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe.get(), &readMode, nullptr, nullptr))
            return HRESULT_FROM_WIN32(GetLastError());
        DWORD written = 0;
        hr = Transfer(pipe.get(), job.request.data(), static_cast<DWORD>(job.request.size()), true, job, &written);
        if (FAILED(hr)) return hr;
        if (written != job.request.size()) return HRESULT_FROM_WIN32(ERROR_WRITE_FAULT);
        std::array<std::uint8_t, kMaxFrameLength> response{};
        DWORD read = 0;
        hr = Transfer(pipe.get(), response.data(), static_cast<DWORD>(response.size()), false, job, &read);
        if (hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA)) return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
        if (FAILED(hr)) return hr;
        if (!job.Remaining()) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
#ifdef PHONEKEY_TRANSPORT_TESTING
        hr = job.recheckPeer ? job.recheckPeer(pipe.get(), process.get()) : CheckServiceBinding(pipe.get(), process.get());
#else
        hr = CheckServiceBinding(pipe.get(), process.get());
#endif
        if (FAILED(hr)) return hr;
        if (!job.Remaining()) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        hr = ValidateAndDecodeResponse(response.data(), read, &job.status, &job.response);
        return FAILED(hr) ? hr : StatusToHresult(job.status);
    }

    unsigned __stdcall ExchangeThread(void* argument)
    {
        ExchangeJob* job = static_cast<ExchangeJob*>(argument);
        try { job->result = ExchangeOnWorker(*job); }
        catch (const std::bad_alloc&) { job->result = E_OUTOFMEMORY; }
        catch (...) { job->result = E_FAIL; }
        SetEvent(job->complete.get());
        // No caller memory or CP/COM object is referenced by this worker.
        // Return through UCRT: it cleans thread state and releases the module
        // reference acquired by _beginthreadex. Do not call ExitThread here.
        job->Release();
        return 0;
    }

    HRESULT Exchange(
        Command command,
        const std::vector<std::uint8_t>& payload,
        phonekey::ServiceStatus* serviceStatus,
        std::vector<std::uint8_t>* responsePayload)
    {
        if (serviceStatus) *serviceStatus = phonekey::ServiceStatus::InternalError;
        if (!responsePayload) return E_POINTER;
        responsePayload->clear();
        ExchangeLock lock;
        if (!lock.acquired) return HRESULT_FROM_WIN32(ERROR_BUSY);
        if (gExchangeThread.get() != INVALID_HANDLE_VALUE)
        {
            const DWORD state = WaitForSingleObject(gExchangeThread.get(), 0);
            if (state != WAIT_OBJECT_0) return HRESULT_FROM_WIN32(ERROR_BUSY);
            gExchangeThread.reset();
        }
        try
        {
            std::unique_ptr<ExchangeJob, JobRelease> job(new ExchangeJob());
            if (!job->complete.get()) return HRESULT_FROM_WIN32(GetLastError());
#ifdef PHONEKEY_TRANSPORT_TESTING
            job->budget = gTestTimeoutMs;
#endif
            HRESULT hr = BuildRequestFrame(command, payload, &job->request);
            if (FAILED(hr)) return hr;
            // UCRT _beginthreadex retains the module containing ExchangeThread
            // until that function returns. This protects a timed-out CP caller
            // that releases its COM object while the worker is still draining.
            job->references.fetch_add(1, std::memory_order_relaxed);
            const uintptr_t rawThread = _beginthreadex(nullptr, 0, ExchangeThread, job.get(), 0, nullptr);
            if (!rawThread)
            {
                const int error = errno;
                job->Release();
                return error == ENOMEM ? E_OUTOFMEMORY : HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
            }
            HANDLE thread = reinterpret_cast<HANDLE>(rawThread);
            gExchangeThread.reset(thread);
            const DWORD wait = WaitForSingleObject(job->complete.get(), job->Remaining());
            if (wait != WAIT_OBJECT_0 || !job->Remaining())
            {
                const DWORD error = wait == WAIT_FAILED ? GetLastError() : ERROR_TIMEOUT;
                job->cancelled.store(true, std::memory_order_release);
                return HRESULT_FROM_WIN32(error);
            }
            if (serviceStatus) *serviceStatus = job->status;
            if (SUCCEEDED(job->result)) *responsePayload = std::move(job->response);
            return job->result;
        }
        catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
        catch (...) { return E_FAIL; }
    }
}

namespace phonekey
{
    HRESULT BeginCredentialProviderLogin(
        const std::wstring& targetSid,
        LoginOperation operation,
        CredentialLoginBeginResult* result,
        ServiceStatus* serviceStatus)
    {
        if (result == nullptr)
        {
            return E_POINTER;
        }

        result->transactionId.clear();
        result->qrWidth = 0;
        result->expiresAtMs = 0;
        result->qrBits.clear();

        std::vector<std::uint8_t> payload;

        payload.push_back(
            static_cast<std::uint8_t>(
                operation));

        HRESULT hr =
            EncodeSid(
                targetSid,
                &payload);

        if (FAILED(hr))
        {
            return hr;
        }

        std::vector<std::uint8_t> response;

        ServiceStatus localStatus =
            ServiceStatus::InternalError;

        ServiceStatus* effectiveStatus =
            serviceStatus != nullptr
                ? serviceStatus
                : &localStatus;

        hr =
            Exchange(
                Command::
                    BeginCredentialProviderLogin,
                payload,
                effectiveStatus,
                &response);

        if (FAILED(hr))
        {
            return hr;
        }

        if (
            *effectiveStatus !=
            ServiceStatus::Success
        )
        {
            return S_OK;
        }

        constexpr std::uint8_t
            kBeginResponseVersion = 2;

        constexpr std::size_t
            kFixedLength = 26;

        if (
            response.size() <
            kFixedLength
        )
        {
            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        if (
            response[0] !=
            kBeginResponseVersion
        )
        {
            return HRESULT_FROM_WIN32(
                ERROR_REVISION_MISMATCH);
        }

        result->transactionId.assign(
            response.begin() + 1,
            response.begin() + 17);

        bool transactionNonZero =
            false;

        for (
            const std::uint8_t value :
            result->transactionId
        )
        {
            if (value != 0)
            {
                transactionNonZero =
                    true;

                break;
            }
        }

        if (!transactionNonZero)
        {
            result->transactionId.clear();

            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        const std::uint8_t width =
            response[17];

        if (
            width < 21 ||
            width > 177 ||
            ((width - 21) % 4) != 0
        )
        {
            result->transactionId.clear();

            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        const std::size_t moduleCount =
            static_cast<std::size_t>(
                width) *
            static_cast<std::size_t>(
                width);

        const std::size_t packedLength =
            (moduleCount + 7) / 8;

        if (
            response.size() !=
            kFixedLength +
                packedLength
        )
        {
            result->transactionId.clear();

            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        result->qrWidth =
            width;

        std::uint64_t expiresAtMs = 0;
        for (std::size_t index = 18; index < 26; ++index)
        {
            expiresAtMs = (expiresAtMs << 8) | response[index];
        }
        if (expiresAtMs == 0)
        {
            result->transactionId.clear();
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        result->expiresAtMs = expiresAtMs;

        result->qrBits.assign(
            response.begin() +
                kFixedLength,
            response.end());

        return S_OK;
    }

    HRESULT CancelCredentialProviderLogin(
        const std::vector<std::uint8_t>& transactionId,
        ServiceStatus* serviceStatus)
    {
        if (
            transactionId.size() !=
            16
        )
        {
            return E_INVALIDARG;
        }

        std::vector<std::uint8_t> response;

        return Exchange(
            Command::
                CancelCredentialProviderLogin,
            transactionId,
            serviceStatus,
            &response);
    }

    HRESULT GetCredentialProviderLoginStatus(
        const std::vector<std::uint8_t>& transactionId,
        CredentialLoginState* loginState,
        ServiceStatus* serviceStatus)
    {
        if (loginState == nullptr)
        {
            return E_POINTER;
        }

        if (
            transactionId.size() !=
            16
        )
        {
            return E_INVALIDARG;
        }

        std::vector<std::uint8_t> response;

        ServiceStatus localStatus =
            ServiceStatus::InternalError;

        ServiceStatus* effectiveStatus =
            serviceStatus != nullptr
                ? serviceStatus
                : &localStatus;

        HRESULT hr =
            Exchange(
                Command::
                    GetCredentialProviderLoginStatus,
                transactionId,
                effectiveStatus,
                &response);

        if (FAILED(hr))
        {
            return hr;
        }

        if (
            *effectiveStatus !=
            ServiceStatus::Success
        )
        {
            return S_OK;
        }

        if (response.size() != 1)
        {
            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        const std::uint8_t state =
            response[0];

        if (
            state <
                static_cast<std::uint8_t>(
                    CredentialLoginState::
                        Pending) ||
            state >
                static_cast<std::uint8_t>(
                    CredentialLoginState::
                        TransportError)
        )
        {
            return HRESULT_FROM_WIN32(
                ERROR_INVALID_DATA);
        }

        *loginState =
            static_cast<
                CredentialLoginState>(
                    state);

        return S_OK;
    }

    HRESULT RedeemCredentialProviderPassword(
        const std::vector<std::uint8_t>& transactionId,
        std::vector<wchar_t>* password,
        ServiceStatus* serviceStatus,
        bool localAccount)
    {
        if (!password) return E_POINTER;
        password->clear();
        if (transactionId.size() != 16) return E_INVALIDARG;
        std::vector<std::uint8_t> response;
        ServiceStatus localStatus = ServiceStatus::InternalError;
        ServiceStatus* effectiveStatus = serviceStatus ? serviceStatus : &localStatus;
        const HRESULT hr = Exchange(localAccount
                ? Command::RedeemCredentialProviderLocalPassword
                : Command::RedeemCredentialProviderPassword,
            transactionId, effectiveStatus, &response);
        if (FAILED(hr)) return hr;
        if (*effectiveStatus != ServiceStatus::Success) return S_OK;
        if (response.empty() || response.size() > 1024 || response.size() % 2 != 0)
        {
            if (!response.empty()) SecureZeroMemory(response.data(), response.size());
            return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }
        password->reserve(response.size() / 2 + 1);
        for (std::size_t index = 0; index < response.size(); index += 2)
        {
            const wchar_t unit = static_cast<wchar_t>(response[index] |
                (static_cast<unsigned>(response[index + 1]) << 8));
            if (unit == 0)
            {
                SecureZeroMemory(response.data(), response.size());
                SecureZeroMemory(password->data(), password->size() * sizeof(wchar_t));
                password->clear();
                return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            }
            password->push_back(unit);
        }
        password->push_back(0);
        SecureZeroMemory(response.data(), response.size());
        return S_OK;
    }
}
