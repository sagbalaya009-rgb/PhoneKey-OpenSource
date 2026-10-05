#include <initguid.h>
#include "../CSampleCredential.h"
#include <iostream>
#include <stdexcept>

// The fixture links the real credential implementation. Its only injected
// state is an already verified handle; it never supplies a password or proof.
void DllAddRef() {}
void DllRelease() {}
HINSTANCE g_hinst = nullptr;

class PhoneKeyCredentialSelectionTestAccess
{
public:
    static void Approve(CSampleCredential* credential, size_t size = 16)
    {
        credential->_fPhoneKeyVerified = true;
        credential->_fPhoneKeySessionActive = false;
        credential->_phoneKeyTransactionId.assign(size, 0x42);
    }
    static bool RetainsApproval(CSampleCredential* credential)
    {
        return credential->_fPhoneKeyVerified &&
            credential->_phoneKeyTransactionId == std::vector<std::uint8_t>(16, 0x42);
    }
};

void Require(bool value, const char* message)
{
    if (!value) throw std::runtime_error(message);
}

int wmain()
{
    const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(com)) return 1;
    auto* credential = new CSampleCredential();
    int result = 0;
    try
    {
        PhoneKeyCredentialSelectionTestAccess::Approve(credential);
        for (int repeat = 0; repeat < 100; ++repeat)
        {
            BOOL autoLogon = FALSE;
            Require(credential->SetSelected(&autoLogon) == S_OK && autoLogon,
                "Reselection discarded verified transaction or failed to submit");
            Require(PhoneKeyCredentialSelectionTestAccess::RetainsApproval(credential),
                "Reselection replaced the verified transaction");
        }
        Require(credential->SetSelected(nullptr) == E_INVALIDARG,
            "Null selection output must be rejected");
        Require(PhoneKeyCredentialSelectionTestAccess::RetainsApproval(credential),
            "Invalid selection call discarded approval");
        Require(credential->SetDeselected() == S_OK, "Deselection failed");
        Require(!PhoneKeyCredentialSelectionTestAccess::RetainsApproval(credential),
            "Deselection must clear approval");
        BOOL autoLogon = TRUE;
        Require(credential->SetSelected(&autoLogon) == S_OK && !autoLogon,
            "Unverified selection must not automatically sign in");
        PhoneKeyCredentialSelectionTestAccess::Approve(credential, 15);
        autoLogon = TRUE;
        Require(credential->SetSelected(&autoLogon) == S_OK && !autoLogon,
            "Malformed transaction must not automatically sign in");
        std::cout << "Credential reselection regression tests passed\n";
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        result = 1;
    }
    credential->Release();
    CoUninitialize();
    return result;
}
