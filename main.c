#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

int readIntAt(int p) { return *(int *) p; }

short readShortAt(int p) { return *(short *) p; }

void *getPEBAddr() {
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
    const int pebAddr = (int) getPEBAddr();
    const int ldr = readIntAt(pebAddr + 0xC);   // Read pointer to LDR
    int modulePtr = readIntAt(ldr + 0x14);      // InMemoryOrderModuleList forward link (1st module)
    modulePtr = readIntAt(modulePtr);           // Follow linked list to 2nd module
    modulePtr = readIntAt(modulePtr);           // Follow linked list to 3rd module
    const int kernelAddr = readIntAt(modulePtr + 0x10);  // At offset 0x10 from the forward ptr is the base address
    const int peRVA = readIntAt(kernelAddr + 0x3C); // kernelAddr points to the DOS header, read PE RVA at 0x3C
    const int peAddr = kernelAddr + peRVA;          // This is the virtual address of the PE header
    const int exportRVA = readIntAt(peAddr + 0x78); // The export table RVA is at 0x78 from the start of PE header
    const int exportAddr = kernelAddr + exportRVA;  // This is the virtual address of the export table

    const int nFunctions = readIntAt(exportAddr + 0x14);  // The number of functions is at 0x14
    const int functionsAddr = readIntAt(exportAddr + 0x1C) + kernelAddr; // RVA of array of function RVAs is at 0x1c
    const int namesAddr =
            readIntAt(exportAddr + 0x20) + kernelAddr;     // RVA of array of function name RVAs is at 0x20
    const int ordinalsAddr = readIntAt(exportAddr + 0x24) + kernelAddr;  // RVA of array of function ordinals is at 0x24

    printf("kernelAddr = %08x\n", kernelAddr);
    printf("peRVA = %08x\n", peRVA);
    printf("peAddr = %08x\n", peAddr);
    printf("exportRVA = %08x\n", exportRVA);
    printf("exportAddr = %08x\n", exportAddr);
    printf("nFunctions = %d\n", nFunctions);
    printf("functionsAddr = %d\n", functionsAddr);
    printf("namesAddr = %d\n", namesAddr);
    printf("ordinalsAddr = %d\n", ordinalsAddr);

    // Iterate the functions and calculate the hashes of their names
    printf("\n\n");
    for (int i = 0, p = namesAddr; i < nFunctions; i++, p += 4) {
        char *name = (char *) (readIntAt(p) + kernelAddr);
        printf("%sHash equ 0x%08x\n", name, hash(name));
    }

    printf("\n\n");
    int functionToFind = 0xD6F0C751;
    for (int i = 0, p = namesAddr; i < nFunctions; i++, p += 4) {
        char *name = (char *) (readIntAt(p) + kernelAddr);
        if (hash(name) == functionToFind) {
            short ordinal = readShortAt(ordinalsAddr + i * 2);                  // get function ordinal
            int functionRVA = readIntAt(functionsAddr + ordinal * 4);           // get function RVA
            int functionAddress = functionRVA + kernelAddr;
            printf("Address of %s is %08xh", name, functionAddress);   // compute function address
            break;
        }
    }

    printf("\n\n");
    return 0;
}


