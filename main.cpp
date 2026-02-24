#include <windows.h>
#include <winhttp.h>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <cctype>
#include <wincrypt.h>
#include <curl/curl.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

std::string sha1(const std::string& input)
{
    BYTE hash[20];
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return ""; }
    CryptHashData(hHash, reinterpret_cast<const BYTE*>(input.c_str()), input.size(), 0);
    DWORD hashLen = 20;
    CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::stringstream ss;
    for (DWORD i = 0; i < hashLen; ++i)
        ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::string getPassword()
{
    std::string pw;
    std::getline(std::cin, pw);
    return pw;
}

bool httpGet(const std::wstring& server, const std::wstring& path, std::string& response)
{
    HINTERNET hSession = WinHttpOpen(L"Password Checker/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, server.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    bool result = false;
    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(hRequest, NULL))
    {
        DWORD dwSize = 0;
        do
        {
            DWORD downloaded = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            if (dwSize == 0) break;
            std::vector<char> buffer(dwSize + 1);
            if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &downloaded)) break;
            buffer[downloaded] = 0;
            response += buffer.data();
        } while (dwSize > 0);
        result = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

int checkPassword(const std::string& hash)
{
    std::string prefix = hash.substr(0, 5);
    std::string suffix = hash.substr(5);
    std::wstring server = L"api.pwnedpasswords.com";
    std::wstring path = L"/range/" + std::wstring(prefix.begin(), prefix.end());

    std::string response;
    if (!httpGet(server, path, response)) return -1;

    std::istringstream iss(response);
    std::string line;
    while (std::getline(iss, line))
    {
        std::string line_upper = line;
        std::transform(line_upper.begin(), line_upper.end(), line_upper.begin(), ::toupper);
        if (line_upper.find(suffix) == 0)
        {
            auto pos = line.find(":");
            if (pos != std::string::npos)
                return std::stoi(line.substr(pos + 1));
        }
    }
    return 0;
}

int main()
{
    while (true)
    {
        system("cls");
        std::cout << "==== Password Leak Checker ====\n\n";
        std::cout << "Please type your password: ";

        std::string password = getPassword();
        if (password.empty())
        {
            std::cout << "Empty input. Restarting...\n";
            std::cin.get();
            continue;
        }

        std::string hash = sha1(password);
        int result = checkPassword(hash);

        std::cout << "\n-------------------------------\n";

        if (result > 0)
            std::cout << "Your password has appeared " << result << " times in the database.\nNo Opsec!!!\n";
        else if (result == 0)
            std::cout << "No occurrence of the password in the database.\n";
        else
            std::cout << "Error checking password.\n";

        std::cout << "Enter your email: ";
        std::string email;
        std::getline(std::cin, email);
        std::string url = "https://haveibeenpwned.com/account/" + email;
        ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);

        std::cout << "\nOpen website? (y/n): ";
        char choice;
        std::cin >> choice;
        std::cin.ignore(1000, '\n');

        if (choice == 'y' || choice == 'Y')
            ShellExecuteA(NULL, "open", "https://haveibeenpwned.com/Passwords", NULL, NULL, SW_SHOWNORMAL);
        ShellExecuteA(NULL, "open", "https://haveibeenpwned.com/", NULL, NULL, SW_SHOWNORMAL);

        std::cout << "\nCheck another password? (y/n): ";
        std::cin >> choice;
        std::cin.ignore(1000, '\n');

        if (choice != 'y' && choice != 'Y')
            break;
    }

    FreeConsole();
    return 0;
}