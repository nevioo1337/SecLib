#include <vector>
#include <iomanip>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "piscosha2.h"

namespace SecLib {
	class FileID {
	private:	
		std::vector<std::vector<std::string>> iconHashes { 
			{"d8f039e909a31dddd945c63166b490907c88acbe0237acce0389f0fc2e92cffa", "dbg"},
			{"0feafee6589ebdf53169d1eb03bfd109b8bdd9c6353a37322c12ab61178008a8", "Fiddler"},
			{"678b44b52a31fe369fd18055e367cccd1061a4096b1fe9a256864666424ebd5d", "x86IDA"},
			{"fadc5e5fea7219f8b8f9297b21bff8d84300fc1ebfcee78b5b0f9d233fa201a5", "x64IDA"},
			{"ac1eb5e8839fa2d33819d03fb5bf3119cb8c7ad317208253130d59a46b964895", "CheatEngine"},
			{"57f302b0be37d8f87c178a7b27082f4098e653e697e260e13065199e843b1113", "ProcessMonitor"},
			{"5bc1aee1070c95a2f43c7be98ee9fc2689f18af9e260bec94831f629ae7d6a56", "ProcessHacker"},
			{"39f6c3384f7c4db2a3532fb0e51bd691d1db6e59141b25f6956b4966753f4d87", "HTTPDebugger"},
			{"b6e889adee6d3c1caec120e0dbf6b24afb0308cfad2eff0b3547e13df1b2bd70", "DebugView"},
			{"31d55a42831f4179a95028b4f25f60af1573c64b66fab1c05af59cafd33c8051", "ReClass"},
			{"0bf48d29cf384683775fbf7a66293d316a981ed3166260d6287695899dac3ce8", "OllyDbg"}
		};

		std::vector<std::vector<std::string>> sigBlacklist {
			{"40 5A 00 00 CD 02 3F 5F 58 6F 75 74 5F 6F 66 5F", "x64dbg"},
			{"6D 69 6E 61 74 65 50 72 6F 63 65 73 73 00 7E 01", "x64dbg"},
			{"E4 98 04 76 44 01 C3 8F DB 5E 8F 72 6E BB EA F8", "x64dbg"},
			{"21 7B 64 0B 05 24 DB BC DF EC AB 4D EF B8 A7 FB", "x64dbg"},
			{"0F 05 32 6F AF 80 34 18 FD 5F 58 60 FE FF EC 73", "x32dbg"},
			{"09 00 B0 65 84 76 4D 91 6E 7F F2 5D CF 7E 99 51", "x32dbg"},
			{"5F 4F BF 4E 9A 77 C7 C5 43 1A 8F C7 3B 64 E2 39", "x32dbg"},
			{"F8 96 BB 4D 53 3E 10 AB F5 5A E4 C6 C1 C2 E6 A1", "x32dbg"},
		};

		std::vector<std::vector<std::string>> stringBlacklist {
			{"Unable to obtain current directory during crash dump", "dbg"}
		};

		std::vector<std::string> hostBlacklist {
			"auth",
			"discord"
		};

		std::vector<std::string> driverBlacklist {
			"HttpDebugger"
		};

		std::string getExeDir() {
			char buffer[MAX_PATH];
			GetModuleFileNameA(NULL, buffer, MAX_PATH);

			return std::string(buffer);
		}

		bool contains(std::string str, std::string substr) {
			std::transform(str.begin(), str.end(), str.begin(), ::tolower);
			std::transform(substr.begin(), substr.end(), substr.begin(), ::tolower);
			return str.find(substr) != std::string::npos;
		}

		std::string readText(std::string path) {
			std::ifstream file(path, std::ios::binary);
			std::string str;
			char c;
			while (file.get(c)) {
				if (isprint(c)) {
					str += c;
				}
				else {
					str += '.';
				}
			}
			return str;
		}

		std::string readHex(std::string path) {
			//_setmode(_fileno(stdout), _O_U16TEXT);
			std::ifstream file(path, std::ios::binary);
			std::stringstream ss;
			if (file.is_open()) {
				std::string line;
				while (std::getline(file, line)) {
					for (auto c : line) {
						//std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)(unsigned char)c << L' ';
						ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c << ' ';
					}
					//std::wcout << std::endl;
				}
				file.close();
			}
			return ss.str();
		}
		
		std::vector<std::string> listProcessPaths() {
			std::vector<std::string> processes;
			HANDLE hProcessSnap;
			PROCESSENTRY32 pe32;
			hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hProcessSnap == INVALID_HANDLE_VALUE) {
				return processes;
			}
			pe32.dwSize = sizeof(PROCESSENTRY32);
			if (!Process32First(hProcessSnap, &pe32)) {
				CloseHandle(hProcessSnap);
				return processes;
			}
			do {
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
				if (hProcess) {
					HMODULE hMod;
					DWORD cbNeeded;
					if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
						char szProcessName[MAX_PATH];
						if (GetModuleFileNameExA(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(char))) {
							if (std::find(processes.begin(), processes.end(), szProcessName) == processes.end()) {
								processes.push_back(szProcessName);
							}
						}
					}
				}
				CloseHandle(hProcess);
			} while (Process32Next(hProcessSnap, &pe32));
			CloseHandle(hProcessSnap);
			return processes;
		}

		std::vector<std::string> listWindows() {
			std::vector<std::string> windows;
			HWND hwnd = GetTopWindow(NULL);
			while (hwnd != NULL) {
				char buffer[MAX_PATH];
				GetWindowTextA(hwnd, buffer, MAX_PATH);
				std::string str(buffer);
				if (str != "") {
					windows.push_back(str);
				}
				hwnd = GetNextWindow(hwnd, GW_HWNDNEXT);
			}
			return windows;
		}

		std::string getIconHash(std::string path) {
			HICON hIcon = ExtractIconA(NULL, path.c_str(), 0);

			std::string hex;

			ICONINFO iconInfo;
			GetIconInfo(hIcon, &iconInfo);
			BITMAP bmp;
			GetObject(iconInfo.hbmColor, sizeof(BITMAP), &bmp);
			int width = bmp.bmWidth;
			int height = bmp.bmHeight;

			HDC hdc = GetDC(NULL);
			HDC hdcMem = CreateCompatibleDC(hdc);
			HBITMAP hbm = CreateCompatibleBitmap(hdc, width, height);
			HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbm);
			DrawIconEx(hdcMem, 0, 0, hIcon, width, height, 0, NULL, DI_NORMAL);
			BITMAPINFO bmpInfo;
			bmpInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
			bmpInfo.bmiHeader.biWidth = width;
			bmpInfo.bmiHeader.biHeight = height;
			bmpInfo.bmiHeader.biPlanes = 1;
			bmpInfo.bmiHeader.biBitCount = 32;
			bmpInfo.bmiHeader.biCompression = BI_RGB;
			bmpInfo.bmiHeader.biSizeImage = 0;
			bmpInfo.bmiHeader.biXPelsPerMeter = 0;
			bmpInfo.bmiHeader.biYPelsPerMeter = 0;
			bmpInfo.bmiHeader.biClrUsed = 0;
			bmpInfo.bmiHeader.biClrImportant = 0;
			std::vector<unsigned char> pixels(width * height * 4);
			GetDIBits(hdcMem, hbm, 0, height, &pixels[0], &bmpInfo, DIB_RGB_COLORS);
			SelectObject(hdcMem, hbmOld);
			DeleteObject(hbm);
			DeleteDC(hdcMem);
			ReleaseDC(NULL, hdc);

			for (int i = 0; i < pixels.size(); i++) {
				std::string hexStr = std::to_string(pixels[i]);
				hex += hexStr;
			}

			std::string hexHash;
			picosha2::hash256_hex_string(hex, hexHash);

			return hexHash;
		}

		bool hasIcon(std::string path) {
			try {
				HICON hIcon = ExtractIconA(NULL, path.c_str(), 0);
				if (hIcon == NULL) {
					return false;
				}
				else {
					return true;
				}
			}
			catch (const std::exception&) {}
		}

		std::vector<std::string> listDrivers() {
			std::vector<std::string> drivers;
			SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
			if (hSCM == NULL) {
				return drivers;
			}
			DWORD dwBytesNeeded;
			DWORD dwServicesReturned;
			DWORD dwResumeHandle = 0;
			EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL);
			LPENUM_SERVICE_STATUS_PROCESS lpServices = (LPENUM_SERVICE_STATUS_PROCESS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesNeeded);
			if (lpServices == NULL) {
				CloseServiceHandle(hSCM);
				return drivers;
			}
			if (!EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, (LPBYTE)lpServices, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
				HeapFree(GetProcessHeap(), 0, lpServices);
				CloseServiceHandle(hSCM);
				return drivers;
			}
			for (DWORD i = 0; i < dwServicesReturned; i++) {
				std::wstring driverWstr(lpServices[i].lpDisplayName);
				std::string driver(driverWstr.begin(), driverWstr.end());
				drivers.push_back(driver);
			}
			HeapFree(GetProcessHeap(), 0, lpServices);
			CloseServiceHandle(hSCM);
			return drivers;
		}

		bool isInHosts(std::string str) {
			std::ifstream file("C:\\Windows\\System32\\drivers\\etc\\hosts");
			std::string line;
			while (std::getline(file, line)) {
				std::transform(line.begin(), line.end(), line.begin(), ::tolower);
				if (line.find(str) != std::string::npos) {
					return true;
				}
			}
			return false;
		}
	public:
		std::vector<std::string> iconCheck() {
			std::vector<std::string> res = { };
			std::vector<std::string> processes = listProcessPaths();
			for (int i = 0; i < processes.size(); i++) {
				if (hasIcon(processes[i])) {
					std::string iconHash = getIconHash(processes[i]);
					for (int j = 0; j < iconHashes.size(); j++) {
						if (iconHash == iconHashes[j][0]) {
							res.push_back(iconHashes[j][1]);
						}
					}
				}
			}
			return res;
		}

		std::vector<std::string> hostCheck() {
			std::vector<std::string> res = { };
			for (int i = 0; i < hostBlacklist.size(); i++) {
				if (isInHosts(hostBlacklist[i])) {
					res.push_back(hostBlacklist[i]);
				}
			}
			return res;
		}

		std::vector<std::string> driverCheck() {
			std::vector<std::string> res = { };
			std::vector<std::string> drivers = listDrivers();
			for (int i = 0; i < drivers.size(); i++) {
				for (int j = 0; j < driverBlacklist.size(); j++) {
					if (drivers[i].find(driverBlacklist[j]) != std::string::npos) {
						res.push_back(drivers[i]);
					}
				}
			}
			return res;
		}

		std::vector<std::string> stringCheck() {
			std::vector<std::string> res = { };
			std::vector<std::string> processes = listProcessPaths();
			for (int i = 0; i < processes.size(); i++) {
				std::string text = readText(processes[i]);
				for (int j = 0; j < stringBlacklist.size(); j++) {
					if (contains(text, stringBlacklist[j][0]) && processes[i] != getExeDir()) {
						res.push_back(stringBlacklist[j][1]);
					}
				}
			}
			return res;
		}

		std::vector<std::string> sigCheck() {
			std::vector<std::string> res = { };
			std::vector<std::string> processes = listProcessPaths();
			for (int i = 0; i < processes.size(); i++) {
				std::string text = readHex(processes[i]);
				for (int j = 0; j < sigBlacklist.size(); j++) {
					if (contains(text, sigBlacklist[j][0]) && processes[i] != getExeDir()) {
						res.push_back(sigBlacklist[j][1]);
					}
				}
			}
			return res;
		}
	};
}