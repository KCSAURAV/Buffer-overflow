
/* Command to compile this program:
  gcc vuln.c -o vuln -fno-stack-protector -z execstack

  -g tells GCC to add extra information for GDB
  -fno-stack-protector flag to turn off stack protection mechanism
  -z execstack, it makes stack executable. 
  
 The CPU’s general purpose registers (Intel, x86) are :

EAX : accumulator : used for performing calculations, and used to store return values
 from function calls. Basic ops such as add, subtract, compare use this general
 -purpose register
EBX : base (does not have anything to do with base pointer). It can be used to store data.
ECX : counter : used for iterations. ECX counts downward.
EDX : data : this is an extension of the EAX register. It allows for more complex calculations (multiply, divide) by allowing extra data to be stored to facilitate those calculations.
ESP : stack pointer
EBP : base pointer - Unique. Frame pointer, register hardware inside CPU
ESI : source index : holds location of input data
EDI : destination index  : points to location of where result of data operation is stored
EIP : instruction pointer  */
#include <stdio.h>
#include <string.h>

void func(char *name){
    char buf[100];
    strcpy(buf, name);
    printf("Welcome %s\n", buf);
}

int main(int argc, char *argv[]){
    func(argv[1]);
    return 0;
}

