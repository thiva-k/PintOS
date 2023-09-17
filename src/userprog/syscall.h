#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init (void);
void exit(int status);
bool isValidPointer(const void * pointer);

#endif /* userprog/syscall.h */
