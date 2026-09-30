//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <propkey.h>

#include <cstdint>
#include <vector>

#include "common.h"
#include "dll.h"
#include "resource.h"
#include "PhoneKeyIpc.h"

class CSampleCredential :
    public ICredentialProviderCredential2,
    public ICredentialProviderCredentialWithFieldOptions
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;

        if (!cRef)
        {
            delete this;
        }

        return cRef;
    }

    IFACEMETHODIMP QueryInterface(
        _In_ REFIID riid,
        _COM_Outptr_ void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(
                CSampleCredential,
                ICredentialProviderCredential),

            QITABENT(
                CSampleCredential,
                ICredentialProviderCredential2),

            QITABENT(
                CSampleCredential,
                ICredentialProviderCredentialWithFieldOptions),

            {0},
        };

        return QISearch(
            this,
            qit,
            riid,
            ppv);
    }

public:
    // ICredentialProviderCredential

    IFACEMETHODIMP Advise(
        _In_ ICredentialProviderCredentialEvents *pcpce);

    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(
        _Out_ BOOL *pbAutoLogon);

    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(
        DWORD dwFieldID,
        _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
        _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis);

    IFACEMETHODIMP GetStringValue(
        DWORD dwFieldID,
        _Outptr_result_nullonfailure_ PWSTR *ppwsz);

    IFACEMETHODIMP GetBitmapValue(
        DWORD dwFieldID,
        _Outptr_result_nullonfailure_ HBITMAP *phbmp);

    IFACEMETHODIMP GetCheckboxValue(
        DWORD dwFieldID,
        _Out_ BOOL *pbChecked,
        _Outptr_result_nullonfailure_ PWSTR *ppwszLabel);

    IFACEMETHODIMP GetComboBoxValueCount(
        DWORD dwFieldID,
        _Out_ DWORD *pcItems,
        _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem);

    IFACEMETHODIMP GetComboBoxValueAt(
        DWORD dwFieldID,
        DWORD dwItem,
        _Outptr_result_nullonfailure_ PWSTR *ppwszItem);

    IFACEMETHODIMP GetSubmitButtonValue(
        DWORD dwFieldID,
        _Out_ DWORD *pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(
        DWORD dwFieldID,
        _In_ PCWSTR pwz);

    IFACEMETHODIMP SetCheckboxValue(
        DWORD dwFieldID,
        BOOL bChecked);

    IFACEMETHODIMP SetComboBoxSelectedValue(
        DWORD dwFieldID,
        DWORD dwSelectedItem);

    IFACEMETHODIMP CommandLinkClicked(
        DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(
        _Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
        _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);

    IFACEMETHODIMP ReportResult(
        NTSTATUS ntsStatus,
        NTSTATUS ntsSubstatus,
        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon);

    // ICredentialProviderCredential2

    IFACEMETHODIMP GetUserSid(
        _Outptr_result_nullonfailure_ PWSTR *ppszSid);

    // ICredentialProviderCredentialWithFieldOptions

    IFACEMETHODIMP GetFieldOptions(
        DWORD dwFieldID,
        _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo);

public:
    HRESULT Initialize(
        CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
        _In_ FIELD_STATE_PAIR const *rgfsp,
        _In_ ICredentialProviderUser *pcpUser);

    CSampleCredential();

private:
    /*
     * Updates only the visible PhoneKey status text.
     * This does not submit or serialize a Windows credential.
     */
    HRESULT UpdatePhoneKeyStatus(
        _In_ PCWSTR text);

    /*
     * Best-effort cleanup for a LocalSystem-owned pending
     * PhoneKey authentication transaction.
     */
    void CancelPhoneKeySessionBestEffort();

    /*
     * Reads only the service-owned PhoneKey transaction state
     * and updates visible UI text. It does not serialize a
     * Windows credential.
     */
    HRESULT RefreshPhoneKeyStatus();

    /*
     * Builds a temporary QR bitmap from the public packed
     * module matrix returned by PhoneKeyService.
     */
    HRESULT CreatePhoneKeyQrBitmap(
        _Out_ HBITMAP* bitmap) const;

    /*
     * Displays the QR in a properly LogonUI-parented window.
     */
    HRESULT ShowPhoneKeyQrDialog();

    virtual ~CSampleCredential();

    long _cRef;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR
        _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];

    FIELD_STATE_PAIR
        _rgFieldStatePairs[SFI_NUM_FIELDS];

    PWSTR
        _rgFieldStrings[SFI_NUM_FIELDS];

    PWSTR _pszUserSid;

    PWSTR _pszQualifiedUserName;

    ICredentialProviderCredentialEvents2*
        _pCredProvCredentialEvents;

    BOOL _fChecked;

    DWORD _dwComboIndex;

    bool _fShowControls;

    bool _fIsLocalUser;

    // Public QR state and a transaction handle. The Windows password is
    // received only transiently in GetSerialization after phone approval.
    bool _fPhoneKeySessionActive;
    bool _fPhoneKeyVerified;

    std::vector<std::uint8_t>
        _phoneKeyTransactionId;

    std::uint8_t
        _phoneKeyQrWidth;

    std::uint64_t
        _phoneKeyQrExpiresAtMs;

    std::vector<std::uint8_t>
        _phoneKeyQrBits;
};

