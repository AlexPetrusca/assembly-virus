#include <stdio.h>
#include <Windows.h>

#define PATH "C:\\Program Files (x86)"
#define MAX_PATH_LENGHT 260
#define STACK_SIZE 100
#define COUNT 30

int main() {
    char* exe = ".exe";
    WIN32_FIND_DATA findData;
    HANDLE handle = NULL;
    int counter = COUNT;
    int eax = 0;
    char *currentPath = (char *) malloc(MAX_PATH_LENGHT);
    char *searchPath = (char *) malloc(MAX_PATH_LENGHT);
    currentPath[0] = 0;
    searchPath[0] = 0;
    char stack[STACK_SIZE * MAX_PATH_LENGHT]; // create and initialize stack
    void *ebp = stack + STACK_SIZE * MAX_PATH_LENGHT;
    void *esp = ebp;
    esp -= MAX_PATH_LENGHT;
    lstrcpyA(esp, PATH);

    NEXT_DIR:
    if (esp == ebp) goto EXIT;
    lstrcpyA(currentPath, esp);               // pop path off the stack
    esp += MAX_PATH_LENGHT;
    lstrcpyA(searchPath, currentPath);
    lstrcatA(searchPath, "\\*.*");            // append the file mask
    handle = FindFirstFile(searchPath, &findData);
    if (handle == (void *) -1) goto CLOSE_SEARCH;
    goto PROCESS_FILE;

    NEXT_FILE:
    eax = FindNextFile(handle, &findData);
    if (eax == 0) goto CLOSE_SEARCH;
    PROCESS_FILE:
    if (findData.cFileName[0] == '.') goto NEXT_FILE;
    lstrcpyA(searchPath, currentPath);
    lstrcatA(searchPath, "\\");
    lstrcatA(searchPath, findData.cFileName);
    if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) goto DIR;
    int i = lstrlenA(findData.cFileName) - 4;
    if (*(int*)(findData.cFileName + i) != 0x6578652E) goto NEXT_FILE;
    printf("File: %s\n", searchPath);
    counter--;
    if (counter == 0) goto EXIT;
    goto NEXT_FILE;
    DIR:
    esp -= MAX_PATH_LENGHT;
    lstrcpyA(esp, searchPath);                // push path to stack
    goto NEXT_FILE;

    CLOSE_SEARCH:
    FindClose(handle);
    goto NEXT_DIR;

    EXIT:
    // do not forget to destroy the stack
    printf("%d", COUNT - counter);
    return 0;
}
