//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"

#pragma comment(lib, "Advapi32.lib")

namespace
{
    // Event IDs only: never write account names, SIDs, QR contents, keys,
    // passwords, or proof bytes from the LogonUI process.
    void RecordPhoneKeySignInEvent(DWORD eventId, WORD eventType = EVENTLOG_INFORMATION_TYPE)
    {
        HANDLE source = RegisterEventSourceW(nullptr, L"PhoneKey Sign-In");
        if (source != nullptr)
        {
            (void)ReportEventW(source, eventType, 0, eventId,
                nullptr, 0, 0, nullptr, nullptr);
            (void)DeregisterEventSource(source);
        }
    }

    constexpr wchar_t
        kPhoneKeyQrWindowClass[] =
            L"PhoneKeyQrWindowV1";

    struct PhoneKeyQrTimerState
    {
        std::uint64_t deadlineTickMs = 0;
        std::uint64_t nextStatusPollTickMs = 0;
        HWND label = nullptr;
        std::vector<std::uint8_t> transactionId;
        phonekey::CredentialLoginState lastLoggedState = phonekey::CredentialLoginState::Pending;
    };

    std::uint64_t PhoneKeyUnixTimeMs()
    {
        FILETIME fileTime = {};
        GetSystemTimeAsFileTime(&fileTime);
        ULARGE_INTEGER ticks = {};
        ticks.LowPart = fileTime.dwLowDateTime;
        ticks.HighPart = fileTime.dwHighDateTime;
        constexpr std::uint64_t epochTicks = 116444736000000000ULL;
        return ticks.QuadPart < epochTicks ? 0 : (ticks.QuadPart - epochTicks) / 10000;
    }

    LRESULT CALLBACK PhoneKeyQrWindowProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam)
    {
        switch (message)
        {
        case WM_NCCREATE:
        {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                reinterpret_cast<LONG_PTR>(create->lpCreateParams));
            break;
        }

        case WM_TIMER:
        {
            auto* state = reinterpret_cast<PhoneKeyQrTimerState*>(
                GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            if (state != nullptr && state->label != nullptr)
            {
                const std::uint64_t now = GetTickCount64();
                const std::uint64_t remaining = state->deadlineTickMs > now
                    ? (state->deadlineTickMs - now + 999) / 1000 : 0;
                wchar_t countdown[48] = {};
                if (remaining == 0)
                {
                    SetWindowTextW(state->label, L"QR expired");
                    KillTimer(hwnd, 1);
                    DestroyWindow(hwnd);
                }
                else if (SUCCEEDED(StringCchPrintfW(countdown, ARRAYSIZE(countdown),
                    L"QR expires in %llu seconds", static_cast<unsigned long long>(remaining))))
                {
                    SetWindowTextW(state->label, countdown);
                }
                if (remaining > 0 && state->transactionId.size() == 16 &&
                    now >= state->nextStatusPollTickMs)
                {
                    state->nextStatusPollTickMs = now + 250;
                    phonekey::CredentialLoginState loginState = phonekey::CredentialLoginState::Pending;
                    phonekey::ServiceStatus serviceStatus = phonekey::ServiceStatus::InternalError;
                    if (SUCCEEDED(phonekey::GetCredentialProviderLoginStatus(
                        state->transactionId, &loginState, &serviceStatus)) &&
                        serviceStatus == phonekey::ServiceStatus::Success)
                    {
                        if (loginState != state->lastLoggedState)
                        {
                            state->lastLoggedState = loginState;
                            DWORD stageEvent = 0;
                            switch (loginState)
                            {
                            case phonekey::CredentialLoginState::Scanning: stageEvent = 4105; break;
                            case phonekey::CredentialLoginState::Connecting: stageEvent = 4106; break;
                            case phonekey::CredentialLoginState::WaitingForProof: stageEvent = 4107; break;
                            case phonekey::CredentialLoginState::Verifying: stageEvent = 4108; break;
                            case phonekey::CredentialLoginState::TransportError: stageEvent = 4191; break;
                            case phonekey::CredentialLoginState::Expired: stageEvent = 4194; break;
                            default: break;
                            }
                            if (stageEvent != 0)
                            {
                                RecordPhoneKeySignInEvent(stageEvent,
                                    stageEvent >= 4190 ? EVENTLOG_WARNING_TYPE : EVENTLOG_INFORMATION_TYPE);
                            }
                        }
                        if (loginState == phonekey::CredentialLoginState::Authenticated ||
                            loginState == phonekey::CredentialLoginState::Rejected ||
                            loginState == phonekey::CredentialLoginState::Expired ||
                            loginState == phonekey::CredentialLoginState::Cancelled ||
                            loginState == phonekey::CredentialLoginState::TransportError)
                        {
                            KillTimer(hwnd, 1);
                            DestroyWindow(hwnd);
                        }
                    }
                }
            }
            return 0;
        }

        case WM_COMMAND:
            if (
                LOWORD(wParam) ==
                IDOK
            )
            {
                DestroyWindow(
                    hwnd);

                return 0;
            }

            break;

        case WM_CLOSE:
            DestroyWindow(
                hwnd);

            return 0;

        case WM_NCDESTROY:
            KillTimer(hwnd, 1);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            break;
        }

        return DefWindowProcW(
            hwnd,
            message,
            wParam,
            lParam);
    }
}

CSampleCredential::CSampleCredential():
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0),
    _fPhoneKeySessionActive(false),
    _fPhoneKeyVerified(false),
    _phoneKeyQrWidth(0),
    _phoneKeyQrExpiresAtMs(0)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    CancelPhoneKeySessionBestEffort();

    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"PhoneKey", &_rgFieldStrings[SFI_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"PhoneKey - Scan QR with your phone", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Edit Text", &_rgFieldStrings[SFI_EDIT_TEXT]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Checkbox", &_rgFieldStrings[SFI_CHECKBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Combobox", &_rgFieldStrings[SFI_COMBOBOX]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Open PhoneKey QR / refresh status", &_rgFieldStrings[SFI_LAUNCHWINDOW_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Hide additional controls", &_rgFieldStrings[SFI_HIDECONTROLS_LINK]);
    }
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszUserName;
        pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
        if (pszUserName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_FULLNAME_TEXT]);
            CoTaskMemFree(pszUserName);
        }
        else
        {
            hr =  SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_FULLNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszDisplayName;
        pcpUser->GetStringValue(PKEY_Identity_DisplayName, &pszDisplayName);
        if (pszDisplayName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Display Name: %s", pszDisplayName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
            CoTaskMemFree(pszDisplayName);
        }
        else
        {
            hr = SHStrDupW(L"Display Name is NULL", &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszLogonStatus;
        pcpUser->GetStringValue(PKEY_Identity_LogonStatusString, &pszLogonStatus);
        if (pszLogonStatus != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Logon Status: %s", pszLogonStatus);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
            CoTaskMemFree(pszLogonStatus);
        }
        else
        {
            hr = SHStrDupW(L"Logon Status is NULL", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        }
    }

    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(
    _Out_ BOOL *pbAutoLogon)
{
    if (pbAutoLogon == nullptr)
    {
        return E_INVALIDARG;
    }

    // QR selection starts a phone challenge. Submission still requires
    // verified proof and a separate one-time service redemption.
    *pbAutoLogon = FALSE;
    RecordPhoneKeySignInEvent(4090); // PhoneKey tile selected.

    // LogonUI can select the same tile again while field updates from the
    // verified QR dialog are being dispatched. Preserve the one-time approved
    // transaction until GetSerialization redeems it; beginning another QR here
    // would overwrite the accepted proof before it can be submitted.
    if (_fPhoneKeyVerified && _phoneKeyTransactionId.size() == 16)
    {
        RecordPhoneKeySignInEvent(4092); // Reused verified transaction on reselection.
        *pbAutoLogon = TRUE;
        return S_OK;
    }

    if (_fPhoneKeySessionActive)
    {
        if (_phoneKeyQrExpiresAtMs > PhoneKeyUnixTimeMs() &&
            !_phoneKeyQrBits.empty() && _pCredProvCredentialEvents != nullptr)
        {
            const HRESULT existingHr = ShowPhoneKeyQrDialog();
            *pbAutoLogon = _fPhoneKeyVerified ? TRUE : FALSE;
            return existingHr;
        }
        CancelPhoneKeySessionBestEffort();
    }

    if (
        _pszUserSid == nullptr ||
        _pszUserSid[0] == L'\0'
    )
    {
        RecordPhoneKeySignInEvent(4195, EVENTLOG_WARNING_TYPE);
        return UpdatePhoneKeyStatus(L"PhoneKey could not identify this Windows account. Use your PIN.");
    }

    // The pilot has separate encrypted local and Microsoft-account vaults.
    // Reject unknown identities before asking the phone to approve a QR.
    constexpr wchar_t msaPrefix[] = L"MicrosoftAccount\\";
    if (_pszQualifiedUserName == nullptr || _pszQualifiedUserName[0] == L'\0' ||
        (!_fIsLocalUser &&
            (_wcsnicmp(_pszQualifiedUserName, msaPrefix, ARRAYSIZE(msaPrefix) - 1) != 0 ||
                _pszQualifiedUserName[ARRAYSIZE(msaPrefix) - 1] == L'\0')))
    {
        return UpdatePhoneKeyStatus(
            L"PhoneKey is not configured for this Windows account. Use your PIN or password.");
    }

    phonekey::LoginOperation operation;

    switch (_cpus)
    {
    case CPUS_LOGON:
        operation =
            phonekey::
                LoginOperation::
                    Logon;
        break;

    case CPUS_UNLOCK_WORKSTATION:
        operation =
            phonekey::
                LoginOperation::
                    Unlock;
        break;

    default:
        return S_OK;
    }

    phonekey::CredentialLoginBeginResult
        beginResult;

    phonekey::ServiceStatus
        serviceStatus =
            phonekey::
                ServiceStatus::
                    InternalError;

    HRESULT hr =
        phonekey::
            BeginCredentialProviderLogin(
                _pszUserSid,
                operation,
                &beginResult,
                &serviceStatus);

    if (FAILED(hr))
    {
        RecordPhoneKeySignInEvent(4196, EVENTLOG_WARNING_TYPE);
        UpdatePhoneKeyStatus(L"PhoneKey could not reach its Windows service. Use your PIN, then repair PhoneKey.");
        return hr;
    }

    if (
        serviceStatus !=
        phonekey::
            ServiceStatus::
                Success
    )
    {
        RecordPhoneKeySignInEvent(4197, EVENTLOG_WARNING_TYPE);
        return UpdatePhoneKeyStatus(L"PhoneKey could not start this sign-in. Use your PIN, then check PhoneKey.");
    }

    if (
        beginResult
            .transactionId
            .size() != 16 ||
        beginResult.qrWidth < 21 ||
        beginResult.qrWidth > 177 ||
        beginResult.expiresAtMs == 0 ||
        beginResult.qrBits.empty()
    )
    {
        return HRESULT_FROM_WIN32(
            ERROR_INVALID_DATA);
    }

    _phoneKeyTransactionId =
        std::move(
            beginResult
                .transactionId);
    _fPhoneKeyVerified = false;

    _phoneKeyQrWidth =
        beginResult.qrWidth;

    _phoneKeyQrExpiresAtMs =
        beginResult.expiresAtMs;

    _phoneKeyQrBits =
        std::move(
            beginResult.qrBits);

    _fPhoneKeySessionActive =
        true;

    RecordPhoneKeySignInEvent(4100); // QR challenge created.

    hr =
        UpdatePhoneKeyStatus(
            L"PhoneKey - Scan the live QR, then approve on your phone.");

    if (FAILED(hr))
    {
        CancelPhoneKeySessionBestEffort();

        return hr;
    }

    /*
     * Show the large QR immediately when LogonUI has supplied
     * its owner HWND. If Advise has not occurred yet, the
     * command link remains a fallback.
     */
    if (
        _pCredProvCredentialEvents !=
        nullptr
    )
    {
        hr =
            ShowPhoneKeyQrDialog();

        if (FAILED(hr))
        {
            CancelPhoneKeySessionBestEffort();

            return hr;
        }
    }

    // The modal QR dialog returns only after phone status has been refreshed.
    // A verified proof may now submit its one-time Windows credential directly.
    *pbAutoLogon = _fPhoneKeyVerified ? TRUE : FALSE;

    return S_OK;
}
// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    RecordPhoneKeySignInEvent(4091); // Explicit tile deselection clears approval.
    CancelPhoneKeySessionBestEffort();

    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));

        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);

        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }

    return hr;
}

HRESULT CSampleCredential::UpdatePhoneKeyStatus(_In_ PCWSTR text)
{
    if (text == nullptr)
    {
        return E_INVALIDARG;
    }

    PWSTR replacement = nullptr;

    HRESULT hr = SHStrDupW(text, &replacement);

    if (FAILED(hr))
    {
        return hr;
    }

    CoTaskMemFree(_rgFieldStrings[SFI_LARGE_TEXT]);

    _rgFieldStrings[SFI_LARGE_TEXT] = replacement;

    if (_pCredProvCredentialEvents != nullptr)
    {
        hr = _pCredProvCredentialEvents->SetFieldString(
            this,
            SFI_LARGE_TEXT,
            _rgFieldStrings[SFI_LARGE_TEXT]);
    }

    return hr;
}

HRESULT CSampleCredential::CreatePhoneKeyQrBitmap(
    _Out_ HBITMAP* bitmap) const
{
    if (bitmap == nullptr)
    {
        return E_POINTER;
    }

    *bitmap =
        nullptr;

    if (
        _phoneKeyQrWidth < 21 ||
        _phoneKeyQrWidth > 177 ||
        ((_phoneKeyQrWidth - 21) % 4) != 0
    )
    {
        return HRESULT_FROM_WIN32(
            ERROR_INVALID_DATA);
    }

    const std::size_t width =
        static_cast<std::size_t>(
            _phoneKeyQrWidth);

    const std::size_t moduleCount =
        width * width;

    const std::size_t packedLength =
        (moduleCount + 7) / 8;

    if (
        _phoneKeyQrBits.size() !=
        packedLength
    )
    {
        return HRESULT_FROM_WIN32(
            ERROR_INVALID_DATA);
    }

    constexpr int quietZone =
        4;

    const int totalModules =
        static_cast<int>(
            width) +
        quietZone * 2;

    int pixelsPerModule =
        8;

    if (
        totalModules *
            pixelsPerModule >
        640
    )
    {
        pixelsPerModule =
            640 /
            totalModules;
    }

    if (pixelsPerModule < 3)
    {
        pixelsPerModule =
            3;
    }

    const int bitmapSize =
        totalModules *
        pixelsPerModule;

    BITMAPINFO info = {};

    info.bmiHeader.biSize =
        sizeof(
            BITMAPINFOHEADER);

    info.bmiHeader.biWidth =
        bitmapSize;

    /*
     * Negative height produces a top-down DIB.
     */
    info.bmiHeader.biHeight =
        -bitmapSize;

    info.bmiHeader.biPlanes =
        1;

    info.bmiHeader.biBitCount =
        32;

    info.bmiHeader.biCompression =
        BI_RGB;

    void* rawPixels =
        nullptr;

    HBITMAP result =
        CreateDIBSection(
            nullptr,
            &info,
            DIB_RGB_COLORS,
            &rawPixels,
            nullptr,
            0);

    if (
        result == nullptr ||
        rawPixels == nullptr
    )
    {
        if (result != nullptr)
        {
            DeleteObject(
                result);
        }

        return HRESULT_FROM_WIN32(
            GetLastError());
    }

    auto* pixels =
        static_cast<
            std::uint32_t*>(
                rawPixels);

    const std::size_t pixelCount =
        static_cast<std::size_t>(
            bitmapSize) *
        static_cast<std::size_t>(
            bitmapSize);

    for (
        std::size_t index = 0;
        index < pixelCount;
        ++index
    )
    {
        pixels[index] =
            0x00FFFFFFu;
    }

    for (
        int y = 0;
        y <
            static_cast<int>(
                width);
        ++y
    )
    {
        for (
            int x = 0;
            x <
                static_cast<int>(
                    width);
            ++x
        )
        {
            const std::size_t module =
                static_cast<std::size_t>(
                    y) *
                    width +
                static_cast<std::size_t>(
                    x);

            const bool dark =
                (
                    _phoneKeyQrBits[
                        module / 8]
                    &
                    static_cast<std::uint8_t>(
                        1u <<
                        (
                            7 -
                            (
                                module %
                                8
                            )
                        )
                    )
                ) != 0;

            if (!dark)
            {
                continue;
            }

            const int startX =
                (
                    x +
                    quietZone
                ) *
                pixelsPerModule;

            const int startY =
                (
                    y +
                    quietZone
                ) *
                pixelsPerModule;

            for (
                int dy = 0;
                dy <
                    pixelsPerModule;
                ++dy
            )
            {
                for (
                    int dx = 0;
                    dx <
                        pixelsPerModule;
                    ++dx
                )
                {
                    const std::size_t
                        pixelIndex =
                            static_cast<
                                std::size_t>(
                                    startY +
                                    dy) *
                                static_cast<
                                    std::size_t>(
                                        bitmapSize)
                            +
                            static_cast<
                                std::size_t>(
                                    startX +
                                    dx);

                    pixels[pixelIndex] =
                        0x00000000u;
                }
            }
        }
    }

    *bitmap =
        result;

    return S_OK;
}

HRESULT CSampleCredential::ShowPhoneKeyQrDialog()
{
    if (
        !_fPhoneKeySessionActive ||
        _phoneKeyQrBits.empty()
    )
    {
        return E_UNEXPECTED;
    }

    if (
        _pCredProvCredentialEvents ==
        nullptr
    )
    {
        return E_UNEXPECTED;
    }

    HWND owner =
        nullptr;

    HRESULT hr =
        _pCredProvCredentialEvents
            ->OnCreatingWindow(
                &owner);

    if (FAILED(hr))
    {
        return hr;
    }

    if (
        owner == nullptr
    )
    {
        return E_UNEXPECTED;
    }

    HBITMAP qrBitmap =
        nullptr;

    hr =
        CreatePhoneKeyQrBitmap(
            &qrBitmap);

    if (FAILED(hr))
    {
        return hr;
    }

    BITMAP bitmapInfo = {};

    if (
        GetObjectW(
            qrBitmap,
            sizeof(bitmapInfo),
            &bitmapInfo) == 0
    )
    {
        const HRESULT objectError =
            HRESULT_FROM_WIN32(
                GetLastError());

        DeleteObject(
            qrBitmap);

        return objectError;
    }

    WNDCLASSEXW windowClass = {};

    windowClass.cbSize =
        sizeof(
            windowClass);

    windowClass.lpfnWndProc =
        PhoneKeyQrWindowProc;

    windowClass.hInstance =
        HINST_THISDLL;

    windowClass.hCursor =
        LoadCursorW(
            nullptr,
            IDC_ARROW);

    windowClass.hbrBackground =
        reinterpret_cast<HBRUSH>(
            COLOR_WINDOW + 1);

    windowClass.lpszClassName =
        kPhoneKeyQrWindowClass;

    if (
        RegisterClassExW(
            &windowClass) == 0
    )
    {
        const DWORD error =
            GetLastError();

        if (
            error !=
            ERROR_CLASS_ALREADY_EXISTS
        )
        {
            DeleteObject(
                qrBitmap);

            return HRESULT_FROM_WIN32(
                error);
        }
    }

    constexpr int margin =
        24;

    constexpr int instructionHeight =
        44;

    constexpr int countdownHeight =
        30;

    constexpr int gap =
        16;

    constexpr int buttonHeight =
        38;

    const int clientWidth =
        bitmapInfo.bmWidth +
        margin * 2;

    const int clientHeight =
        margin +
        instructionHeight +
        countdownHeight +
        bitmapInfo.bmHeight +
        gap +
        buttonHeight +
        margin;

    RECT desired = {
        0,
        0,
        clientWidth,
        clientHeight
    };

    if (
        !AdjustWindowRectEx(
            &desired,
            WS_CAPTION |
                WS_SYSMENU |
                WS_POPUP,
            FALSE,
            WS_EX_DLGMODALFRAME)
    )
    {
        const HRESULT adjustError =
            HRESULT_FROM_WIN32(
                GetLastError());

        DeleteObject(
            qrBitmap);

        return adjustError;
    }

    const int windowWidth =
        desired.right -
        desired.left;

    const int windowHeight =
        desired.bottom -
        desired.top;

    RECT ownerRect = {};

    int x =
        CW_USEDEFAULT;

    int y =
        CW_USEDEFAULT;

    if (
        GetWindowRect(
            owner,
            &ownerRect)
    )
    {
        x =
            ownerRect.left +
            (
                ownerRect.right -
                ownerRect.left -
                windowWidth
            ) / 2;

        y =
            ownerRect.top +
            (
                ownerRect.bottom -
                ownerRect.top -
                windowHeight
            ) / 2;
    }

    PhoneKeyQrTimerState timerState = {};
    const std::uint64_t wallNow = PhoneKeyUnixTimeMs();
    const std::uint64_t wallRemainingMs = _phoneKeyQrExpiresAtMs > wallNow
        ? _phoneKeyQrExpiresAtMs - wallNow : 0;
    const std::uint64_t remainingMs = wallRemainingMs < 60000
        ? wallRemainingMs : 60000;
    timerState.deadlineTickMs = GetTickCount64() + remainingMs;
    timerState.transactionId = _phoneKeyTransactionId;

    HWND window =
        CreateWindowExW(
            WS_EX_DLGMODALFRAME,
            kPhoneKeyQrWindowClass,
            L"PhoneKey - Scan QR",
            WS_CAPTION |
                WS_SYSMENU |
                WS_POPUP,
            x,
            y,
            windowWidth,
            windowHeight,
            owner,
            nullptr,
            HINST_THISDLL,
            &timerState);

    if (window == nullptr)
    {
        const HRESULT createError =
            HRESULT_FROM_WIN32(
                GetLastError());

        DeleteObject(
            qrBitmap);

        return createError;
    }

    HWND instruction =
        CreateWindowExW(
            0,
            L"STATIC",
            L"Scan this live QR with PhoneKey and approve on your phone. The window closes automatically after verification.",
            WS_CHILD |
                WS_VISIBLE |
                SS_CENTER,
            margin,
            margin,
            bitmapInfo.bmWidth,
            instructionHeight,
            window,
            nullptr,
            HINST_THISDLL,
            nullptr);

    HWND image =
        CreateWindowExW(
            0,
            L"STATIC",
            L"",
            WS_CHILD |
                WS_VISIBLE |
                SS_BITMAP |
                SS_CENTERIMAGE,
            margin,
            margin +
                instructionHeight +
                countdownHeight,
            bitmapInfo.bmWidth,
            bitmapInfo.bmHeight,
            window,
            nullptr,
            HINST_THISDLL,
            nullptr);

    HWND closeButton =
        CreateWindowExW(
            0,
            L"BUTTON",
            L"Close and refresh status",
            WS_CHILD |
                WS_VISIBLE |
                BS_DEFPUSHBUTTON,
            margin,
            margin +
                instructionHeight +
                countdownHeight +
                bitmapInfo.bmHeight +
                gap,
            bitmapInfo.bmWidth,
            buttonHeight,
            window,
            reinterpret_cast<HMENU>(
                static_cast<INT_PTR>(
                    IDOK)),
            HINST_THISDLL,
            nullptr);

    HWND countdown = CreateWindowExW(
        0, L"STATIC", L"QR expires in 60 seconds",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        margin, margin + instructionHeight,
        bitmapInfo.bmWidth, countdownHeight,
        window, nullptr, HINST_THISDLL, nullptr);

    timerState.label = countdown;

    if (
        instruction == nullptr ||
        countdown == nullptr ||
        image == nullptr ||
        closeButton == nullptr
    )
    {
        DestroyWindow(
            window);

        DeleteObject(
            qrBitmap);

        return HRESULT_FROM_WIN32(
            GetLastError());
    }

    SendMessageW(
        image,
        STM_SETIMAGE,
        IMAGE_BITMAP,
        reinterpret_cast<LPARAM>(
            qrBitmap));

    EnableWindow(
        owner,
        FALSE);

    ShowWindow(
        window,
        SW_SHOW);

    if (SetTimer(window, 1, 250, nullptr) == 0)
    {
        const DWORD timerError = GetLastError();
        DestroyWindow(window);
        EnableWindow(owner, TRUE);
        DeleteObject(qrBitmap);
        return HRESULT_FROM_WIN32(timerError);
    }

    UpdateWindow(
        window);

    SetForegroundWindow(
        window);

    SendMessageW(window, WM_TIMER, 1, 0);

    MSG message = {};

    while (
        IsWindow(
            window)
    )
    {
        const BOOL result =
            GetMessageW(
                &message,
                nullptr,
                0,
                0);

        if (result == -1)
        {
            DestroyWindow(
                window);

            EnableWindow(
                owner,
                TRUE);

            DeleteObject(
                qrBitmap);

            return HRESULT_FROM_WIN32(
                GetLastError());
        }

        if (result == 0)
        {
            PostQuitMessage(
                static_cast<int>(
                    message.wParam));

            break;
        }

        TranslateMessage(
            &message);

        DispatchMessageW(
            &message);
    }

    EnableWindow(
        owner,
        TRUE);

    SetForegroundWindow(
        owner);

    DeleteObject(
        qrBitmap);

    return RefreshPhoneKeyStatus();
}
HRESULT CSampleCredential::RefreshPhoneKeyStatus()
{
    if (!_fPhoneKeySessionActive)
    {
        return S_OK;
    }

    if (
        _phoneKeyTransactionId.size() !=
        16
    )
    {
        return HRESULT_FROM_WIN32(
            ERROR_INVALID_DATA);
    }

    phonekey::CredentialLoginState
        loginState =
            phonekey::
                CredentialLoginState::
                    Pending;

    phonekey::ServiceStatus
        serviceStatus =
            phonekey::
                ServiceStatus::
                    InternalError;

    const HRESULT hr =
        phonekey::
            GetCredentialProviderLoginStatus(
                _phoneKeyTransactionId,
                &loginState,
                &serviceStatus);

    if (FAILED(hr))
    {
        return hr;
    }

    if (
        serviceStatus !=
        phonekey::
            ServiceStatus::
                Success
    )
    {
        return S_OK;
    }

    switch (loginState)
    {
    case phonekey::
        CredentialLoginState::
            Pending:

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Preparing authentication...");

    case phonekey::
        CredentialLoginState::
            Scanning:

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Scan the live QR with your phone.");

    case phonekey::
        CredentialLoginState::
            Connecting:

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Connecting to your phone...");

    case phonekey::
        CredentialLoginState::
            WaitingForProof:

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Waiting for phone approval...");

    case phonekey::
        CredentialLoginState::
            Verifying:

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Verifying signed phone proof...");

    case phonekey::
        CredentialLoginState::
            Authenticated:

        _fPhoneKeySessionActive =
            false;
        _fPhoneKeyVerified = true;
        RecordPhoneKeySignInEvent(4101); // Phone proof accepted.
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldState(
                this, SFI_SUBMIT_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);
        }

        _phoneKeyQrWidth =
            0;

        _phoneKeyQrBits.clear();
        _phoneKeyQrExpiresAtMs = 0;

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Phone verified. Select Submit to sign in.");

    case phonekey::
        CredentialLoginState::
            Rejected:

        _fPhoneKeySessionActive =
            false;

        _phoneKeyTransactionId.clear();
        _phoneKeyQrWidth = 0;
        _phoneKeyQrBits.clear();
        _phoneKeyQrExpiresAtMs = 0;

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Authentication rejected.");

    case phonekey::
        CredentialLoginState::
            Expired:

        _fPhoneKeySessionActive =
            false;

        _phoneKeyTransactionId.clear();
        _phoneKeyQrWidth = 0;
        _phoneKeyQrBits.clear();
        _phoneKeyQrExpiresAtMs = 0;

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Authentication expired. Reselect the tile for a fresh QR.");

    case phonekey::
        CredentialLoginState::
            Cancelled:

        _fPhoneKeySessionActive =
            false;

        _phoneKeyTransactionId.clear();
        _phoneKeyQrWidth = 0;
        _phoneKeyQrBits.clear();
        _phoneKeyQrExpiresAtMs = 0;

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Authentication cancelled.");

    case phonekey::
        CredentialLoginState::
            TransportError:

        _fPhoneKeySessionActive =
            false;

        _phoneKeyTransactionId.clear();
        _phoneKeyQrWidth = 0;
        _phoneKeyQrBits.clear();
        _phoneKeyQrExpiresAtMs = 0;

        return UpdatePhoneKeyStatus(
            L"PhoneKey - Phone connection failed.");
    }

    return HRESULT_FROM_WIN32(
        ERROR_INVALID_DATA);
}
void CSampleCredential::CancelPhoneKeySessionBestEffort()
{
    if (
        _fPhoneKeySessionActive &&
        _phoneKeyTransactionId.size() ==
            16
    )
    {
        phonekey::ServiceStatus
            ignoredStatus =
                phonekey::
                    ServiceStatus::
                        InternalError;

        (void)phonekey::
            CancelCredentialProviderLogin(
                _phoneKeyTransactionId,
                &ignoredStatus);
    }

    _fPhoneKeySessionActive =
        false;
    _fPhoneKeyVerified = false;
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->SetFieldState(
            this, SFI_SUBMIT_BUTTON, CPFS_HIDDEN);
    }

    _phoneKeyTransactionId.clear();

    _phoneKeyQrWidth =
        0;

    _phoneKeyQrBits.clear();
    _phoneKeyQrExpiresAtMs = 0;
}
// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        if (dwFieldID == SFI_SUBMIT_BUTTON && _fPhoneKeyVerified)
        {
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
        }
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    HRESULT hr;

    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to
        // appear next to.
        *pdwAdjacentTo = SFI_LARGE_TEXT;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    HRESULT hr;
    *ppwszLabel = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pbChecked = _fChecked;
        hr = SHStrDupW(_rgFieldStrings[SFI_CHECKBOX], ppwszLabel);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    CREDENTIAL_PROVIDER_FIELD_STATE cpfsShow = CPFS_HIDDEN;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        switch (dwFieldID)
        {
        case SFI_LAUNCHWINDOW_LINK:
            hr =
                RefreshPhoneKeyStatus();

            if (
                SUCCEEDED(hr) &&
                _fPhoneKeySessionActive &&
                !_phoneKeyQrBits.empty()
            )
            {
                hr =
                    ShowPhoneKeyQrDialog();
            }

            break;
        case SFI_HIDECONTROLS_LINK:
            _pCredProvCredentialEvents->BeginFieldUpdates();
            cpfsShow = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_FULLNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_DISPLAYNAME_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_LOGONSTATUS_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_CHECKBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_EDIT_TEXT, cpfsShow);
            _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_COMBOBOX, cpfsShow);
            _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_HIDECONTROLS_LINK, _fShowControls? L"Hide additional controls" : L"Show additional controls");
            _pCredProvCredentialEvents->EndFieldUpdates();
            _fShowControls = !_fShowControls;
            break;
        default:
            hr = E_INVALIDARG;
        }

    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(
    _Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
    _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
    _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    if (pcpgsr == nullptr ||
        pcpcs == nullptr ||
        ppwszOptionalStatusText == nullptr ||
        pcpsiOptionalStatusIcon == nullptr)
    {
        return E_INVALIDARG;
    }

    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    const HRESULT refreshHr = RefreshPhoneKeyStatus();

    if (FAILED(refreshHr))
    {
        return refreshHr;
    }

    if (!_fPhoneKeyVerified || _phoneKeyTransactionId.size() != 16)
    {
        return S_OK;
    }
    // LogonUI supplies the exact qualified local or Microsoft identity.
    constexpr wchar_t msaPrefix[] = L"MicrosoftAccount\\";
    if (!_pszQualifiedUserName || _pszQualifiedUserName[0] == 0 ||
        (!_fIsLocalUser &&
            (_wcsnicmp(_pszQualifiedUserName, msaPrefix, ARRAYSIZE(msaPrefix) - 1) != 0 ||
                _pszQualifiedUserName[ARRAYSIZE(msaPrefix) - 1] == 0)))
    {
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }

    std::vector<wchar_t> password;
    RecordPhoneKeySignInEvent(4102); // Credential redemption starting.
    phonekey::ServiceStatus serviceStatus = phonekey::ServiceStatus::InternalError;
    HRESULT hr = phonekey::RedeemCredentialProviderPassword(
        _phoneKeyTransactionId, &password, &serviceStatus, _fIsLocalUser);
    _fPhoneKeyVerified = false;
    _phoneKeyTransactionId.clear();
    if (FAILED(hr) || serviceStatus != phonekey::ServiceStatus::Success)
    {
        RecordPhoneKeySignInEvent(4190, EVENTLOG_WARNING_TYPE);
        if (!password.empty()) SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        const HRESULT statusHr = SHStrDupW(
            L"PhoneKey could not finish this sign-in. Select PhoneKey again for a fresh QR, or use your Windows PIN.",
            ppwszOptionalStatusText);
        if (SUCCEEDED(statusHr))
        {
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
            return S_OK;
        }
        return statusHr;
    }

    const DWORD packFlags = _fIsLocalUser ? 0 : CRED_PACK_ID_PROVIDER_CREDENTIALS;
    DWORD packedSize = 0;
    (void)CredPackAuthenticationBufferW(packFlags,
        _pszQualifiedUserName, password.data(), nullptr, &packedSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || packedSize == 0 || packedSize > 8192)
    {
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }
    BYTE* packed = static_cast<BYTE*>(CoTaskMemAlloc(packedSize));
    if (!packed)
    {
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        return E_OUTOFMEMORY;
    }
    const BOOL packedOk = CredPackAuthenticationBufferW(packFlags,
        _pszQualifiedUserName, password.data(), packed, &packedSize);
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    if (!packedOk)
    {
        const HRESULT error = HRESULT_FROM_WIN32(GetLastError());
        SecureZeroMemory(packed, packedSize);
        CoTaskMemFree(packed);
        return error;
    }
    ULONG authPackage = 0;
    hr = RetrieveNegotiateAuthPackage(&authPackage);
    if (FAILED(hr))
    {
        SecureZeroMemory(packed, packedSize);
        CoTaskMemFree(packed);
        return hr;
    }
    pcpcs->ulAuthenticationPackage = authPackage;
    pcpcs->clsidCredentialProvider = CLSID_CSample;
    pcpcs->cbSerialization = packedSize;
    pcpcs->rgbSerialization = packed;
    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    RecordPhoneKeySignInEvent(4103); // Serialized credential handed to Windows.

    return S_OK;
}
struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Windows rejected PhoneKey's saved account password. Use your PIN, then refresh the password in PhoneKey.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (FAILED(HRESULT_FROM_NT(ntsStatus)))
    {
        RecordPhoneKeySignInEvent(4192, EVENTLOG_WARNING_TYPE);
        if (ntsStatus == STATUS_LOGON_FAILURE)
        {
            RecordPhoneKeySignInEvent(4193, EVENTLOG_WARNING_TYPE);
        }
        if (_pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");
        }
    }
    else
    {
        RecordPhoneKeySignInEvent(4104); // Windows accepted the credential.
    }

    // Since nullptr is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}







