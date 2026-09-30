#define PHONEKEY_TRANSPORT_TESTING
#include "../PhoneKeyIpc.cpp"
namespace {
    HANDLE enteredEvent;
    HANDLE releaseEvent;
    HRESULT HoldPeer(HANDLE, HandleGuard&)
    {
        SetEvent(enteredEvent);
        WaitForSingleObject(releaseEvent, INFINITE);
        return S_OK;
    }
}
extern "C" __declspec(dllexport) HRESULT __cdecl RunLifetimeProbe(const wchar_t* pipe, HANDLE entered, HANDLE release)
{
    gTestPipeName = pipe;
    gTestTimeoutMs = 150;
    gTestVerifyPeer = HoldPeer;
    enteredEvent = entered;
    releaseEvent = release;
    std::vector<std::uint8_t> response;
    return Exchange(Command::GetCredentialProviderLoginStatus, std::vector<std::uint8_t>(16, 1), nullptr, &response);
}
