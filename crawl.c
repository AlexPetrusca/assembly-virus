#include <stdio.h>
#include <Windows.h>
#include <winnt.h>

#define PATH "C:\\Program Files (x86)"
#define MAX_PATH_LENGHT 260
#define STACK_SIZE 2000
#define COUNT 100000

char *getAttrString(char *s, DWORD a) {
    s[0] = 0;
    if ((FILE_ATTRIBUTE_READONLY & a) != 0) strcat(s, "R ");
    if ((FILE_ATTRIBUTE_HIDDEN & a) != 0) strcat(s, "H ");
    if ((FILE_ATTRIBUTE_SYSTEM & a) != 0) strcat(s, "S ");
    if ((FILE_ATTRIBUTE_DIRECTORY & a) != 0) strcat(s, "D ");
    if ((FILE_ATTRIBUTE_ARCHIVE & a) != 0) strcat(s, "A ");
    if ((FILE_ATTRIBUTE_DEVICE & a) != 0) strcat(s, "DEV ");
    if ((FILE_ATTRIBUTE_NORMAL & a) != 0) strcat(s, "N ");
    if ((FILE_ATTRIBUTE_TEMPORARY & a) != 0) strcat(s, "T ");
    if ((FILE_ATTRIBUTE_SPARSE_FILE & a) != 0) strcat(s, "SPARSE ");
    if ((FILE_ATTRIBUTE_REPARSE_POINT & a) != 0) strcat(s, "RP ");
    if ((FILE_ATTRIBUTE_COMPRESSED & a) != 0) strcat(s, "C ");
    if ((FILE_ATTRIBUTE_OFFLINE & a) != 0) strcat(s, "O ");
    if ((FILE_ATTRIBUTE_NOT_CONTENT_INDEXED & a) != 0) strcat(s, "NCI ");
    if ((FILE_ATTRIBUTE_ENCRYPTED & a) != 0) strcat(s, "E ");
    if ((FILE_ATTRIBUTE_VIRTUAL & a) != 0) strcat(s, "V ");
//    if ((FILE_ATTRIBUTE_VALID_FLAGS & a) != 0) strcat(s, " ");
//    if ((FILE_ATTRIBUTE_VALID_SET_FLAGS & a) != 0) strcat(s, " ");
    return s;
}

int main() {
    char *attributes = malloc(1024);
    WIN32_FIND_DATA findData;
    HANDLE handle = NULL;
    int counter = COUNT, dirCount = 1;
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
    dirCount--;
    lstrcpyA(searchPath, currentPath);
    lstrcatA(searchPath, "\\*.*");            // append the file mask
    handle = FindFirstFile(searchPath, &findData);
    if (handle == (void *) -1) goto CLOSE_SEARCH;
    goto PROCESS_FILE;

    NEXT_FILE:
    eax = FindNextFile(handle, &findData);
    if (eax == 0) goto CLOSE_SEARCH;

    PROCESS_FILE:
    if (findData.cFileName[0] == '.' && findData.cFileName[1] == 0) goto NEXT_FILE;
    if (findData.cFileName[0] == '.' && findData.cFileName[1] == '.') goto NEXT_FILE;
    lstrcpyA(searchPath, currentPath);
    lstrcatA(searchPath, "\\");
    lstrcatA(searchPath, findData.cFileName);
    if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) goto DIR;
    int i = lstrlenA(findData.cFileName) - 4;
    if (*(int *) (findData.cFileName + i) != 0x6578652E) goto NEXT_FILE;  // is the file a .exe?
    printf("FILE = %s\n", searchPath);
    counter--;
    if (counter == 0) goto EXIT;
    goto NEXT_FILE;

    DIR:
    printf("DIR = %s: %s\n", searchPath, getAttrString(attributes, findData.dwFileAttributes));
    if (dirCount < STACK_SIZE) {
        esp -= MAX_PATH_LENGHT;
        lstrcpyA(esp, searchPath);                // push path to stack
        dirCount++;
    } else {
        printf("FILE = %s\n", searchPath);
    }
    goto NEXT_FILE;

    CLOSE_SEARCH:
    FindClose(handle);
    goto NEXT_DIR;

    EXIT:
    // do not forget to destroy the stack
    printf("%d", COUNT - counter);
    return 0;
}

