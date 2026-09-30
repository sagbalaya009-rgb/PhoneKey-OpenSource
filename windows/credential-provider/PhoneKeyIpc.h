#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace phonekey
{
    enum class LoginOperation : std::uint8_t
    {
        Logon = 1,
        Unlock = 2,
    };

    enum class ServiceStatus : std::uint8_t
    {
        Success = 0,
        BadRequest = 1,
        Unauthorized = 2,
        Conflict = 3,
        Expired = 4,
        CryptographicRejection = 5,
        InternalError = 255,
    };

    enum class CredentialLoginState : std::uint8_t
    {
        Pending = 1,
        Scanning = 2,
        Connecting = 3,
        WaitingForProof = 4,
        Verifying = 5,
        Authenticated = 6,
        Rejected = 7,
        Expired = 8,
        Cancelled = 9,
        TransportError = 10,
    };

    struct CredentialLoginBeginResult
    {
        std::vector<std::uint8_t>
            transactionId;

        std::uint8_t
            qrWidth = 0;

        std::uint64_t
            expiresAtMs = 0;

        std::vector<std::uint8_t>
            qrBits;
    };

    HRESULT BeginCredentialProviderLogin(
        const std::wstring& targetSid,
        LoginOperation operation,
        CredentialLoginBeginResult* result,
        ServiceStatus* serviceStatus = nullptr);

    HRESULT CancelCredentialProviderLogin(
        const std::vector<std::uint8_t>& transactionId,
        ServiceStatus* serviceStatus = nullptr);

    HRESULT GetCredentialProviderLoginStatus(
        const std::vector<std::uint8_t>& transactionId,
        CredentialLoginState* loginState,
        ServiceStatus* serviceStatus = nullptr);

    // Returns a single-use secret only after the service verifies phone proof.
    HRESULT RedeemCredentialProviderPassword(
        const std::vector<std::uint8_t>& transactionId,
        std::vector<wchar_t>* password,
        ServiceStatus* serviceStatus = nullptr,
        bool localAccount = false);
}


