#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>        // Must come before windows.h
#include <windows.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libwebsockets.h>
#include <sqlite3.h>
#include <dpapi.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

#define MAX_PATH_LENGTH 1024
#define BUFFER_SIZE 4096
#define LOG_INFO 1
#define LOG_ERROR 2

// Structure to hold client context
struct ClientContext {
    char client_id[32];
    char name[64];
    int status; // 0 = offline, 1 = online
    struct lws* wsi;
    volatile int running;
    HANDLE connect_thread;
    HANDLE activity_thread;
};

// Global context
static struct ClientContext* g_client = NULL;
static CRITICAL_SECTION cs;

// Logging function
void log_message(int level, const char* format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    SYSTEMTIME st;
    GetLocalTime(&st);
    char timestamp[32];
    sprintf(timestamp, "%04d-%02d-%02d %02d:%02d:%02d", 
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    
    FILE* log_file = fopen("client.log", "a");
    if (log_file) {
        fprintf(log_file, "[%s] %s - %s\n", 
                timestamp, 
                level == LOG_INFO ? "INFO" : "ERROR", 
                buffer);
        fclose(log_file);
    }
}

// Generate unique client ID
void generate_client_id(char* id_out) {
    FILE* file = fopen("used_client_ids.txt", "r+");
    if (!file) file = fopen("used_client_ids.txt", "w+");
    
    char used_ids[1024][32] = {0};
    int count = 0;
    if (file) {
        while (fgets(used_ids[count], 32, file) && count < 1024) {
            used_ids[count][strcspn(used_ids[count], "\n")] = 0;
            count++;
        }
    }
    
    while (1) {
        sprintf(id_out, "%03d-%03d-%03d", 
                rand() % 1000, rand() % 1000, rand() % 1000);
        
        int is_unique = 1;
        for (int i = 0; i < count; i++) {
            if (strcmp(id_out, used_ids[i]) == 0) {
                is_unique = 0;
                break;
            }
        }
        
        if (is_unique) {
            if (file) {
                fseek(file, 0, SEEK_END);
                fprintf(file, "%s\n", id_out);
                fclose(file);
            }
            break;
        }
    }
}

// Get system information (simplified version)
void get_system_info(char* buffer, size_t buffer_size) {
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computer_name);
    GetComputerNameA(computer_name, &size);
    
    OSVERSIONINFO osvi = { sizeof(OSVERSIONINFO) };
    GetVersionEx(&osvi);
    
    MEMORYSTATUSEX mem = { sizeof(MEMORYSTATUSEX) };
    GlobalMemoryStatusEx(&mem);
    
    snprintf(buffer, buffer_size,
            "{\"computer_name\":\"%s\","
            "\"windows_version\":\"%d.%d.%d\","
            "\"memory_total\":%.2f,"
            "\"memory_free\":%.2f}",
            computer_name,
            osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber,
            mem.ullTotalPhys / (1024.0 * 1024.0 * 1024.0),
            mem.ullAvailPhys / (1024.0 * 1024.0 * 1024.0));
}

// WebSocket callback
static int callback_client(struct lws* wsi, enum lws_callback_reasons reason, 
                         void* user, void* in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            EnterCriticalSection(&cs);
            g_client->status = 1;
            g_client->wsi = wsi;
            log_message(LOG_INFO, "Connected to server");
            LeaveCriticalSection(&cs);
            break;
            
        case LWS_CALLBACK_CLIENT_RECEIVE:
            log_message(LOG_INFO, "Received: %.*s", (int)len, (char*)in);
            break;
            
        case LWS_CALLBACK_CLIENT_CLOSED:
            EnterCriticalSection(&cs);
            g_client->status = 0;
            log_message(LOG_INFO, "Connection closed");
            LeaveCriticalSection(&cs);
            break;
            
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            EnterCriticalSection(&cs);
            g_client->status = 0;
            log_message(LOG_ERROR, "Connection error: %s", in ? (char*)in : "unknown");
            LeaveCriticalSection(&cs);
            break;
    }
    return 0;
}

// Send status
void send_status() {
    if (!g_client || g_client->status != 1 || !g_client->wsi) return;
    
    char sys_info[BUFFER_SIZE];
    get_system_info(sys_info, sizeof(sys_info));
    
    char payload[BUFFER_SIZE];
    snprintf(payload, sizeof(payload),
            "{\"client_id\":\"%s\","
            "\"name\":\"%s\","
            "\"status\":\"online\","
            "\"system_info\":%s}",
            g_client->client_id, g_client->name, sys_info);
    
    unsigned char* buffer = malloc(LWS_PRE + strlen(payload) + 1);
    if (buffer) {
        memcpy(buffer + LWS_PRE, payload, strlen(payload));
        lws_write(g_client->wsi, buffer + LWS_PRE, strlen(payload), LWS_WRITE_TEXT);
        free(buffer);
    }
}

// Activity simulation thread
DWORD WINAPI activity_thread(LPVOID param) {
    while (g_client->running) {
        if (g_client->status == 1) {
            send_status();
        }
        Sleep((rand() % 6 + 5) * 1000); // 5-10 seconds
    }
    return 0;
}

// Connection thread
DWORD WINAPI connect_thread(LPVOID param) {
    struct lws_context* context;
    struct lws_context_creation_info info = {0};
    struct lws_client_connect_info ccinfo = {0};
    
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = (struct lws_protocols[]){
        {"client-protocol", callback_client, 0, 0},
        {NULL, NULL, 0, 0}
    };
    
    while (g_client->running) {
        context = lws_create_context(&info);
        if (!context) {
            log_message(LOG_ERROR, "Failed to create context");
            Sleep(5000);
            continue;
        }
        
        ccinfo.context = context;
        ccinfo.address = "192.168.1.2";
        ccinfo.port = 8000;
        ccinfo.path = "/ws";
        ccinfo.host = ccinfo.address;
        ccinfo.origin = ccinfo.address;
        ccinfo.protocol = "client-protocol";
        
        if (!lws_client_connect_via_info(&ccinfo)) {
            log_message(LOG_ERROR, "Connection failed");
            lws_context_destroy(context);
            Sleep(5000);
            continue;
        }
        
        while (g_client->running && !lws_service(context, 1000));
        
        lws_context_destroy(context);
        if (g_client->running) {
            log_message(LOG_INFO, "Reconnecting in 5 seconds...");
            Sleep(5000);
        }
    }
    return 0;
}

int main() {
    // Initialize
    srand((unsigned)time(NULL));
    InitializeCriticalSection(&cs);
    
    g_client = malloc(sizeof(struct ClientContext));
    if (!g_client) return 1;
    
    generate_client_id(g_client->client_id);
    snprintf(g_client->name, sizeof(g_client->name), 
            "Windows_Client_%s", g_client->client_id);
    g_client->status = 0;
    g_client->running = 1;
    
    // Start threads
    g_client->connect_thread = CreateThread(NULL, 0, connect_thread, NULL, 0, NULL);
    g_client->activity_thread = CreateThread(NULL, 0, activity_thread, NULL, 0, NULL);
    
    // Main loop
    while (1) {
        Sleep(1000);
        if (GetAsyncKeyState(VK_CONTROL) && GetAsyncKeyState('C')) {
            log_message(LOG_INFO, "Shutting down...");
            break;
        }
    }
    
    // Cleanup
    g_client->running = 0;
    WaitForSingleObject(g_client->connect_thread, INFINITE);
    WaitForSingleObject(g_client->activity_thread, INFINITE);
    CloseHandle(g_client->connect_thread);
    CloseHandle(g_client->activity_thread);
    DeleteCriticalSection(&cs);
    free(g_client);
    
    return 0;
}