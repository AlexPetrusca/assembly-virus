#include <stdio.h>
#include <stdlib.h>

void *getPEB() {
    void *pTIB;
    __asm__("movl %%fs:0x30, %0" : "=r" (pTIB) : : );
    return pTIB;
}

int hash(char *s) {
    int h = 0;
    while (*s != 0) {
        h = (h << 5) - h + *s;
        s++;
    }
    return h;
}

int main() {
    int peb = getPEB();
    int ldr = *(int *) (peb + 0xC);
    int module1 = *(int *) (ldr + 0x14);
    int module2 = *(int *) (module1);
    int module3 = *(int *) (module2);
    int kernelAddr = *(int *) (module3 + 0x10);
    int peOffset = *(int *) (kernelAddr + 0x3C);
    int peAddr = kernelAddr + peOffset;
    int exportRVA = *(int *) (peAddr + 0x78);
    int exportAddr = kernelAddr + exportRVA;
    int nFunctions = *(int *) (exportAddr + 0x14);
    int nNames = *(int *) (exportAddr + 0x18);
    int addressOfFunctions = *(int *) (exportAddr + 0x1c) + kernelAddr;
    int addressOfNames = *(int *) (exportAddr + 0x20) + kernelAddr;
    int addressOfOrdinals = *(int *) (exportAddr + 0x24) + kernelAddr;

    printf("kernelAddr = %08x\n", kernelAddr);
    printf("peOffset = %08x\n", peOffset);
    printf("peAddr = %08x\n", peAddr);
    printf("exportRVA = %08x\n", exportRVA);
    printf("exportAddr = %08x\n", exportAddr);
    printf("nFunctions = %d\n", nFunctions);
    printf("nNames = %d\n", nNames);
    printf("addressOfFunctions = %d\n", addressOfFunctions);
    printf("addressOfNames = %d\n", addressOfNames);
    printf("addressOfOrdinals = %d\n", addressOfOrdinals);

    printf("\n\n");

    int functionToFind = 0x79e4b02e;

    for(int y = 0; y < 200; y++) {
        int p = addressOfNames;
        for (int i = 0; i < nFunctions; i++) {
            char *name = *(int *) p + kernelAddr;
            int h = hash(name);
            //printf("%s - %08x\n", (char*)name, h);
            if (h == functionToFind) {
                short ordinal = *(short *) (addressOfOrdinals + i * 2);
                int address = *(int *) (addressOfFunctions + ordinal * 4);
                printf("Address of %s is %08x", name, address + kernelAddr);
                break;
            }
            p += 4;
        }
    }

/*
    for (int i = 0; i < nFunctions; i++) {
        char* nameAddr = *(int*)addressOfNames + kernelAddr;
        int h = hash(nameAddr);
        printf("%s - %08x\n", nameAddr, h);
        addressOfNames += 4;
    }
*/

    return 0;
}

