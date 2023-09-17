#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "list.h"
#include "devices/shutdown.h"
#include "devices/block.h"

static void syscall_handler (struct intr_frame *);
static struct lock file_lock;

// Helper functions
bool isValidPointer(const void * pointer);
static bool create_new_file(const char *file_name, unsigned file_size);
static int open_file(const char *file);
void exit(int status);
static int write_to_file(int fd, const void* buffer, unsigned size);
struct file_details * get_open_file_details(int fd);
static int read_file(int fd, const void* buffer, unsigned size);
void close_file(int fd);

struct file_details{
  int fd;
  struct file *cur_file;
  struct list_elem elem;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  // thread_exit ();

  int *data_pointer = f->esp;

  uint32_t *argv0 = data_pointer + 1;
  uint32_t *argv1 = data_pointer + 2;
  uint32_t *argv2 = data_pointer + 3;

  if (!isValidPointer(data_pointer) || !isValidPointer(argv0) || !isValidPointer(argv1) || !isValidPointer(argv2)){
    exit(-1);
  }

  int systemCall = *(int *)f->esp;

//   static bool 
// remove(const char *file)
// {
//   if (!is_valid_filename(file))
//     return false;

//   bool status;

//   lock_acquire(&filesys_lock);
//   status = filesys_remove(file);
//   lock_release(&filesys_lock);

//   return status;
// }
  struct file_details *currentFileDet;

  switch(systemCall){
    case SYS_HALT:
      shutdown_power_off();
      break;
    
    case SYS_EXIT:
      exit(*argv0);
      break;
    
    case SYS_EXEC:
      // if (!isValidPointer((char *)argv0))
      //   exit(-1);

      lock_acquire(&file_lock);
      f->eax = process_execute((char *)*argv0);
      lock_release(&file_lock);

      break;
    
    case SYS_WAIT:
      f->eax = process_wait(*argv0);
      break;
    
    case SYS_CREATE:
      f->eax = create_new_file((char *)*argv0, *argv1);
      break;
    
    case SYS_REMOVE:
      // if (!isValidPointer(argv0)){
      //   exit(-1);
      // }

      lock_acquire(&file_lock);
      f->eax = filesys_remove((char *)*argv0);
      lock_release(&file_lock);
      break;
    
    case SYS_OPEN:
      f->eax = open_file((char *)*argv0);
      break;
    
    case SYS_FILESIZE:
      currentFileDet = get_open_file_details(*argv0);
      lock_acquire(&file_lock);
      if (currentFileDet != NULL){
        f->eax = file_length(currentFileDet->cur_file);
      }
      else{
        f->eax = -1;
      }
      lock_release(&file_lock);
      break;

    case SYS_READ:
      f->eax = read_file(*argv0, (void *)*argv1, *argv2);
      break;
    
    case SYS_WRITE:
      f->eax = write_to_file(*argv0, (void *)*argv1, *argv2);
      break;

    case SYS_SEEK:
      currentFileDet = get_open_file_details( *argv0 );
      if (currentFileDet != NULL){
        lock_acquire(&file_lock);
        file_seek(currentFileDet->cur_file, *((unsigned*) argv1));
        lock_release(&file_lock);
      }
      break;
    
    case SYS_TELL:
      // if (isValidPointer(*argv0)){
      currentFileDet = get_open_file_details(*((int*) argv0));
      if (currentFileDet == NULL){
        f->eax = -1;
      }
      else{
        lock_acquire(&file_lock);
        f->eax = file_tell(currentFileDet->cur_file);
        lock_release(&file_lock);
      }        
      // }
      // else{
      //   exit(-1);
      // }
      break;
    
    case SYS_CLOSE:
      close_file(* argv0);
      break;
    
    default:
      break;
  }
}

bool isValidPointer(const void * pointer){
  // Pointer is NULL
  if(pointer == NULL){
    return false;
  }

  // Check if it is a user (address in the user section not in kernel) virtual address
  if (!is_user_vaddr(pointer)){
    return false;
  }

  // Returns the kernel virtual address corresponding to that physical address, 
  // or a null pointer if UADDR is unmapped.
  // i.e pointer should be mapped to a virtual address
  if (!pagedir_get_page(thread_current()->pagedir, pointer)){
    return false;
  }

  return true;
}

static bool 
create_new_file(const char *file_name, unsigned file_size){
  if (!isValidPointer(file_name)){
    exit(-1);
  }

  lock_acquire(&file_lock);

  bool status = filesys_create(file_name, file_size);

  lock_release(&file_lock);

  return status;
}

static int 
open_file(const char *file)
{
  int fd = -1;

  // Invalid pointer
  if (!isValidPointer(file))
    exit(-1);

  // Acquire the lock, so no other file can access
  lock_acquire(&file_lock);

  // Get the list of files
  struct list *open_file_list = &thread_current()->files;

  // Open using the predefined command in filesys section
  struct file *file_struct = filesys_open(file);

  // If the file is open
  if (file_struct != NULL){
    // Insert to the list of open files
    struct file_details *currentFileDet = malloc(sizeof(struct file_details));    
    currentFileDet->fd = thread_current()->fd_count;
    thread_current()->fd_count++;
    currentFileDet->cur_file = file_struct;
    fd = currentFileDet->fd;

    // Insert the struct
    list_push_back(&thread_current()->files, &currentFileDet->elem);
    // list_insert_ordered(open_file_list, &currentFileDet->elem, (list_less_func *)priority_cmp_less_than_func, NULL);
  }

  // Release the lock
  lock_release(&file_lock);

  return fd;
}

static int
read_file(int fd, const void* buffer, unsigned size){

  // Check the pointer for the begining of the buffer is valid or not
  // i.e Check if it exists in the virtual memory and in the user space
  if (!isValidPointer(buffer))
    exit(-1);
  
  // Check the pointer for the ending of the buffer is valid or not
  if (!isValidPointer(buffer + size - 1))
    exit(-1);
  
  int ret = -1;

  
  // Get the input from the console
  if (fd == 0){
    uint8_t* bp = buffer;
    uint8_t c;
    // Get while the input is not null
    unsigned int cnt;
    for (int i=0; i<size; i++){
      c = input_getc();
      if (c == 0)
        break;
      bp[i] = c;
      cnt ++;
    }
    bp++;
    *bp = 0;

    // Set up the stack pointer value
    ret = size-cnt;
  }
  else{
    struct file_details* currentFileDet = get_open_file_details(fd);
    if (currentFileDet != NULL){
      lock_acquire(&file_lock);
      ret = file_read(currentFileDet->cur_file, buffer, size);
      lock_release(&file_lock);
    }
  }

  return ret;
}

static int
write_to_file(int fd, const void* buffer, unsigned size){
  // Can't write to a null pointer
  if (buffer == NULL)
    exit(-1);
  
  // Check the pointer for the begining of the buffer is valid or not
  // i.e Check if it exists in the virtual memory and in the user space
  if (!isValidPointer(buffer))
    exit(-1);
  
  // Check the pointer for the ending of the buffer is valid or not
  if (!isValidPointer(buffer + size -1))
    exit(-1);
  
  lock_acquire(&file_lock);

  int status = 0;

  // Write to the console
  if (fd == 1){
    putbuf(buffer, size);
    status = size;
  }
  else{
    struct file_details *currentFileDet = get_open_file_details(fd);

    if (currentFileDet != NULL){
      status = file_write(currentFileDet->cur_file, buffer, size);
    }
  }

  lock_release(&file_lock);

  return status;
}

void
close_file(int fd){

  struct list_elem *e;
  struct list files = thread_current()->files;

  for (e = list_begin (&files); e != list_end (&files); e = list_next (e))
    {
      struct file_details *currentFileDet = list_entry (e, struct file_details, elem);

      // If found return
      if (currentFileDet->fd == fd){
        lock_acquire(&file_lock);

        file_close(currentFileDet->cur_file);
        list_remove(&currentFileDet->elem);

        lock_release(&file_lock);

        break;
      }
      
      // since the list is sorted, we can return once the fd value exceeds
      // else if (currentFileDet->fd > fd)
      //   return NULL;
    }

  // struct file_details *currentFileDet = get_open_file_details(fd);

  // if (currentFileDet == NULL){
  //   return;
  // }

  // lock_acquire(&file_lock);
  // file_close(currentFileDet->cur_file);
  // lock_release(&file_lock);
}

void 
exit(int status)
{
  printf("%s: exit(%d)\n",thread_current()->name,status);

  thread_current()->parent->ex = true;
  thread_current()->exit_code = status;
  thread_exit();
}

/* Traverses through the list and returns the details of the file if it is open. Otherwise NULL */
struct file_details *
get_open_file_details(int fd){

  struct list_elem *e;
  struct list files = thread_current()->files;

  for (e = list_begin (&files); e != list_end (&files); e = list_next (e))
    {
      struct file_details *currentFileDet = list_entry (e, struct file_details, elem);

      // If found return
      if (currentFileDet->fd == fd){
        return currentFileDet;
      }
      
      // since the list is sorted, we can return once the fd value exceeds
      // else if (currentFileDet->fd > fd)
      //   return NULL;
    }

  return NULL;
}