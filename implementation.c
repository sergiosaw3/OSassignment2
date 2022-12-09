/*

  MyFS: a tiny file-system written for educational purposes

  MyFS is

  Copyright 2018-21 by

  University of Alaska Anchorage, College of Engineering.

  Copyright 2022

  University of Texas at El Paso, Department of Computer Science.

  Contributors: Christoph Lauter
                Dimitri Lyon
                ... and
                ...

  and based on

  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall myfs.c implementation.c `pkg-config fuse --cflags --libs` -o myfs

*/

#include <stddef.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>


/* The filesystem you implement must support all the 13 operations
   stubbed out below. There need not be support for access rights,
   links, symbolic links. There needs to be support for access and
   modification times and information for statfs.

   The filesystem must run in memory, using the memory of size
   fssize pointed to by fsptr. The memory comes from mmap and
   is backed with a file if a backup-file is indicated. When
   the filesystem is unmounted, the memory is written back to
   that backup-file. When the filesystem is mounted again from
   the backup-file, the same memory appears at the newly mapped
   in virtual address. The filesystem datastructures hence must not
   store any pointer directly to the memory pointed to by fsptr; it
   must rather store offsets from the beginning of the memory region.

   When a filesystem is mounted for the first time, the whole memory
   region of size fssize pointed to by fsptr reads as zero-bytes. When
   a backup-file is used and the filesystem is mounted again, certain
   parts of the memory, which have previously been written, may read
   as non-zero bytes. The size of the memory region is at least 2048
   bytes.

   CAUTION:

   * You MUST NOT use any global variables in your program for reasons
   due to the way FUSE is designed.

   You can find ways to store a structure containing all "global" data
   at the start of the memory region representing the filesystem.

   * You MUST NOT store (the value of) pointers into the memory region
   that represents the filesystem. Pointers are virtual memory
   addresses and these addresses are ephemeral. Everything will seem
   okay UNTIL you remount the filesystem again.

   You may store offsets/indices (of type size_t) into the
   filesystem. These offsets/indices are like pointers: instead of
   storing the pointer, you store how far it is away from the start of
   the memory region. You may want to define a type for your offsets
   and to write two functions that can convert from pointers to
   offsets and vice versa.

   * You may use any function out of libc for your filesystem,
   including (but not limited to) malloc, calloc, free, strdup,
   strlen, strncpy, strchr, strrchr, memset, memcpy. However, your
   filesystem MUST NOT depend on memory outside of the filesystem
   memory region. Only this part of the virtual memory address space
   gets saved into the backup-file. As a matter of course, your FUSE
   process, which implements the filesystem, MUST NOT leak memory: be
   careful in particular not to leak tiny amounts of memory that
   accumulate over time. In a working setup, a FUSE process is
   supposed to run for a long time!

   It is possible to check for memory leaks by running the FUSE
   process inside valgrind:

   valgrind --leak-check=full ./myfs --backupfile=test.myfs ~/fuse-mnt/ -f

   However, the analysis of the leak indications displayed by valgrind
   is difficult as libfuse contains some small memory leaks (which do
   not accumulate over time). We cannot (easily) fix these memory
   leaks inside libfuse.

   * Avoid putting debug messages into the code. You may use fprintf
   for debugging purposes but they should all go away in the final
   version of the code. Using gdb is more professional, though.

   * You MUST NOT fail with exit(1) in case of an error. All the
   functions you have to implement have ways to indicated failure
   cases. Use these, mapping your internal errors intelligently onto
   the POSIX error conditions.

   * And of course: your code MUST NOT SEGFAULT!

   It is reasonable to proceed in the following order:

   (1)   Design and implement a mechanism that initializes a filesystem
         whenever the memory space is fresh. That mechanism can be
         implemented in the form of a filesystem handle into which the
         filesystem raw memory pointer and sizes are translated.
         Check that the filesystem does not get reinitialized at mount
         time if you initialized it once and unmounted it but that all
         pieces of information (in the handle) get read back correctly
         from the backup-file.

   (2)   Design and implement functions to find and allocate free memory
         regions inside the filesystem memory space. There need to be
         functions to free these regions again, too. Any "global" variable
         goes into the handle structure the mechanism designed at step (1)
         provides.

   (3)   Carefully design a data structure able to represent all the
         pieces of information that are needed for files and
         (sub-)directories.  You need to store the location of the
         root directory in a "global" variable that, again, goes into the
         handle designed at step (1).

   (4)   Write __myfs_getattr_implem and debug it thoroughly, as best as
         you can with a filesystem that is reduced to one
         function. Writing this function will make you write helper
         functions to traverse paths, following the appropriate
         subdirectories inside the file system. Strive for modularity for
         these filesystem traversal functions.

   (5)   Design and implement __myfs_readdir_implem. You cannot test it
         besides by listing your root directory with ls -la and looking
         at the date of last access/modification of the directory (.).
         Be sure to understand the signature of that function and use
         caution not to provoke segfaults nor to leak memory.

   (6)   Design and implement __myfs_mknod_implem. You can now touch files
         with

         touch foo

         and check that they start to exist (with the appropriate
         access/modification times) with ls -la.

   (7)   Design and implement __myfs_mkdir_implem. Test as above.

   (8)   Design and implement __myfs_truncate_implem. You can now
         create files filled with zeros:

         truncate -s 1024 foo

   (9)   Design and implement __myfs_statfs_implem. Test by running
         df before and after the truncation of a file to various lengths.
         The free "disk" space must change accordingly.

   (10)  Design, implement and test __myfs_utimens_implem. You can now
         touch files at different dates (in the past, in the future).

   (11)  Design and implement __myfs_open_implem. The function can
         only be tested once __myfs_read_implem and __myfs_write_implem are
         implemented.

   (12)  Design, implement and test __myfs_read_implem and
         __myfs_write_implem. You can now write to files and read the data
         back:

         echo "Hello world" > foo
         echo "Hallo ihr da" >> foo
         cat foo

         Be sure to test the case when you unmount and remount the
         filesystem: the files must still be there, contain the same
         information and have the same access and/or modification
         times.

   (13)  Design, implement and test __myfs_unlink_implem. You can now
         remove files.

   (14)  Design, implement and test __myfs_unlink_implem. You can now
         remove directories.

   (15)  Design, implement and test __myfs_rename_implem. This function
         is extremely complicated to implement. Be sure to cover all
         cases that are documented in man 2 rename. The case when the
         new path exists already is really hard to implement. Be sure to
         never leave the filessystem in a bad state! Test thoroughly
         using mv on (filled and empty) directories and files onto
         inexistant and already existing directories and files.

   (16)  Design, implement and test any function that your instructor
         might have left out from this list. There are 13 functions
         __myfs_XXX_implem you have to write.

   (17)  Go over all functions again, testing them one-by-one, trying
         to exercise all special conditions (error conditions): set
         breakpoints in gdb and use a sequence of bash commands inside
         your mounted filesystem to trigger these special cases. Be
         sure to cover all funny cases that arise when the filesystem
         is full but files are supposed to get written to or truncated
         to longer length. There must not be any segfault; the user
         space program using your filesystem just has to report an
         error. Also be sure to unmount and remount your filesystem,
         in order to be sure that it contents do not change by
         unmounting and remounting. Try to mount two of your
         filesystems at different places and copy and move (rename!)
         (heavy) files (your favorite movie or song, an image of a cat
         etc.) from one mount-point to the other. None of the two FUSE
         processes must provoke errors. Find ways to test the case
         when files have holes as the process that wrote them seeked
         beyond the end of the file several times. Your filesystem must
         support these operations at least by making the holes explicit
         zeros (use dd to test this aspect).

   (18)  Run some heavy testing: copy your favorite movie into your
         filesystem and try to watch it out of the filesystem.

*/

/* Helper types and functions */

//typedef size_t off_t;
#define MYFS_MAXIMUM_NAME_LENGTH (255)
#define MYFS_STATIC_PATH_BUF_SIZE (8192)
#define MYFS_TRUNCATE_SMALL_ALLOCATE ((size_t) 512)
#define MYFS_MAGIC (0xCAFEBABE)

typedef enum
{
    DIRECTORY,
    REG_FILE
} __myfs_inode_type_t;

struct __myfs_memory_block_struct{
    size_t size;            /* Includes size of header */
    size_t user_size;
    off_t next;
}; typedef struct __myfs_memory_block_struct *__myfs_memory_block_t;

struct __myfs_handle_struct{
    uint32_t magic;
    off_t free_memory; /* Points to the first block of memory*/
    off_t root_dir;
    size_t size;
}; typedef struct __myfs_handle_struct *__myfs_handle_t;

struct __myfs_file_block_struct_t{
    size_t size;
    size_t allocated;
    off_t next;
    off_t data;
}; typedef struct __myfs_file_block_struct_t __myfs_file_block_t;

struct __myfs_inode_file_struct_t{
    size_t size;
    off_t first_block;
}; typedef struct __myfs_inode_file_struct_t __myfs_inode_file_t;

struct __myfs_inode_directory_struct_t{
    size_t allocated_children;
    size_t number_children;
    off_t children; /* Array of pointers */  /* First Child is ".", second is ".." */
}; typedef struct __myfs_inode_directory_struct_t __myfs_inode_directory_t;

struct __myfs_inode_struct_t{
    __myfs_inode_type_t type;
    char name[MYFS_MAXIMUM_NAME_LENGTH];
    struct timespec times[2];
    union{
        __myfs_inode_file_t file;
        __myfs_inode_directory_t directory;
    } value;
}; typedef struct __myfs_inode_struct_t __myfs_inode_t;


void *__off_to_ptr(__myfs_handle_t handle, off_t offset) {
    if (offset == 0) return NULL;
    if (handle == NULL) return NULL;
    return (void *)(((void *)handle) + offset);
}

off_t __ptr_to_off(__myfs_handle_t handle, void *ptr) {
    if (ptr == NULL) return 0;

    return (off_t) (ptr - (void *)handle);
}
/* Memory housekeeping functions*/
static int __try_size_t_multiply(size_t *c, size_t a, size_t b) {
    size_t t, r, q;

    /* If any of the arguments a and b is zero, everthing works just fine. */
    if ((a == ((size_t) 0)) ||
        (b == ((size_t) 0))) {
        *c = a * b;
        return 1;
    }

    /* Here, neither a nor b is zero.
       We perform the multiplication, which may overflow, i.e. present
       some modulo-behavior.
    */
    t = a * b;

    /* Perform Euclidian division on t by a:
       t = a * q + r
       As we are sure that a is non-zero, we are sure
       that we will not divide by zero.
    */
    q = t / a;
    r = t % a;

    /* If the rest r is non-zero, the multiplication overflowed. */
    if (r != ((size_t) 0)) return 0;

    /* Here the rest r is zero, so we are sure that t = a * q.
       If q is different from b, the multiplication overflowed.
       Otherwise we are sure that t = a * b.
    */
    if (q != b) return 0;
    *c = t;
    return 1;
}


/* returns the offset of the start of the data section of the memory block */
off_t __allocate_mem_block(__myfs_handle_t handle, size_t rawsize) {
    size_t nmemb, size;
    __myfs_memory_block_t prev, curr, new;

    if (rawsize == ((size_t) 0)) return 0;

    size = rawsize-((size_t)1)+sizeof(struct __myfs_memory_block_struct);
    nmemb = size + sizeof(struct __myfs_memory_block_struct);
    if (nmemb < size) return 0;

    nmemb /= sizeof(struct __myfs_memory_block_struct);
    if(!__try_size_t_multiply(&size, nmemb, sizeof(struct __myfs_memory_block_struct))) return 0;
    /* Iterate through free blocks until it reaches the end of the map.	*/
    for(curr = (__myfs_memory_block_t) __off_to_ptr(handle, handle->free_memory), prev = NULL;
        curr != NULL;
        curr = (__myfs_memory_block_t) __off_to_ptr(handle, (prev = curr)->next)) {

        if (curr->size >= size) {
            if ((curr->size - size) < sizeof(struct __myfs_memory_block_struct)) {
                if (prev == NULL) {
                    handle->free_memory = curr->next;
                }else{
                    prev->next = curr->next;
                }
                return __ptr_to_off(handle, ((void*)curr)+sizeof(struct __myfs_memory_block_struct));
            }else{
                new = (__myfs_memory_block_t) (((void *) curr) + size);
                new->size = curr->size - size;
                new->next = curr->next;
                if (prev == NULL) {
                    handle->free_memory = __ptr_to_off(handle, new);
                }else{
                    prev->next = __ptr_to_off(handle,new);
                }
                curr->size = size;
                return __ptr_to_off(handle, ((void*)curr)+sizeof(struct __myfs_memory_block_struct));
            }
        }
    }
    return 0;
}
void __merge_blocks(__myfs_handle_t handle);
/*
Takes the handle and offset of the beginning of the data of a memory block
        The data comes right after the header.
*/
void __free_mem_block(__myfs_handle_t handle, off_t block_offset) {
		if(block_offset == 0) {
			__merge_blocks(handle);
			return;
		}
		
    __myfs_memory_block_t prev, curr, block;
    prev = NULL;
    curr = (__myfs_memory_block_t) __off_to_ptr(handle, handle->free_memory);
    block = (__myfs_memory_block_t) __off_to_ptr(handle, block_offset - sizeof(struct __myfs_memory_block_struct));

    for(curr = (__myfs_memory_block_t) __off_to_ptr(handle, handle->free_memory),prev = NULL;
        curr != NULL;
        curr = (__myfs_memory_block_t) __off_to_ptr(handle, (prev = curr)->next)){
        if (prev == NULL && curr>block){
            block->next= __ptr_to_off(handle,curr);
            __merge_blocks(handle);
            return;
        }

        if (curr>block && prev<block){
            block->next = __ptr_to_off(handle,curr);
            prev->next = __ptr_to_off(handle,block);
            __merge_blocks(handle);
            return;
        }
    }
    if (curr == NULL && prev<block){
        prev->next = __ptr_to_off(handle,block);
        __merge_blocks(handle);
        return;
    }
    __merge_blocks(handle);
    return;
}
void __merge_blocks(__myfs_handle_t handle) {
    __myfs_memory_block_t next, curr;
    curr = (__myfs_memory_block_t) __off_to_ptr(handle,handle->free_memory);

    while(curr->next != 0) {
        /* Algorithm to combine cells */
        while(curr->next != __ptr_to_off(handle, curr) + curr->size) { //Blocks are adjacent
            next = (__myfs_memory_block_t) __off_to_ptr(handle, curr->next);
            curr->size += next->size;
            curr->next = next->next;
        }
        /* Increment to the next node */
        curr = (__myfs_memory_block_t) __off_to_ptr(handle, curr->next);
    }
}

/*	Attempts to resize the memory block with its data section beginning at ptr
		Returns offset of the data section of the memory block

		if new_size == 0, will treat as call to free and return 0.

		Sets *errnoptr to 0 on success and -1 on failure to resize


		*/
off_t __resize_mem_block(__myfs_handle_t handle, off_t ptr, size_t new_size, int *errnoptr){
    /* Declare variables */
    size_t nmemb, size;
    __myfs_memory_block_t relevant, new;
    __myfs_memory_block_t before, after;
    char next_node_adjacent = 0;
    size_t size_change;

    //get the old block
    relevant = (__myfs_memory_block_t) __off_to_ptr(handle, ptr - sizeof(struct __myfs_memory_block_struct));

    //Check if trying to resize to 0.
    if (new_size == ((size_t) 0)) {
        *errnoptr = 0;
        __free_mem_block(handle, ptr);
        return 0;
    }

    /* Math to determine block size */
    size = new_size-((size_t)1)+ sizeof(struct __myfs_memory_block_struct);
    nmemb = size + sizeof(struct __myfs_memory_block_struct);
    //Detect overflow.
    if (nmemb < size) {
        *errnoptr = -1;
        return ptr;
    }

    //Convert to number of blocks
    nmemb /= sizeof(struct __myfs_memory_block_struct);

    //Check for overflow.
    if(!__try_size_t_multiply(&size, nmemb, sizeof(struct __myfs_memory_block_struct))) {
        *errnoptr = -1;
        return ptr;
    }

    //Check if trying to resize to effectively the same size.
    if(size == relevant->size) {
        *errnoptr = 0;
        return ptr;
    }


    before = NULL;
    after = (__myfs_memory_block_t) __off_to_ptr(handle, handle->free_memory);
    /*	Need to get the nearest free memory blocks before and after relevant*/
    while (after < relevant) {
        before = after;
        after = (__myfs_memory_block_t) __off_to_ptr(handle, after->next);
    }

    /*	Check if the next node is adjacent to relevant*/
    if(__ptr_to_off(handle, relevant) + relevant->size == __ptr_to_off(handle, after)) {
        next_node_adjacent = 1;
    }

    /*	At this point, the new size is not the same as the old size.
            It is either larger or smaller. */
    if(size < relevant->size) {
        //Need to shrink memory block.
        size_change = relevant->size - size;
        //Will need to take memory away from relevant and if either
        //Add it to the next node if it is adjacent and free
        //Create a new node and insert it into list if it large enough.

        if(next_node_adjacent) {
            //Expand next node
            new = (__myfs_memory_block_t) (((void *) relevant) + size);

            memcpy((void *) new,(void *)after, sizeof(struct __myfs_memory_block_struct));
            new->size += size_change;
            new->user_size += size_change;
            if(before == NULL) {
                handle->free_memory = __ptr_to_off(handle, new);
            } else {
                before->next = __ptr_to_off(handle, new);
            }

            relevant->size = size;
            relevant->user_size -= size_change;

        } else if (size_change > sizeof(struct __myfs_memory_block_struct)){
            // Can create new node
            new = (__myfs_memory_block_t) (((void *) relevant) + size);
            new->size = size_change;
            new->user_size = size_change - sizeof(struct __myfs_memory_block_struct);
            if(before == NULL) {
                handle->free_memory = __ptr_to_off(handle, new);
            } else {
                before->next = __ptr_to_off(handle, new);
            }
            new->next = __ptr_to_off(handle,after);

            relevant->size = size;
            relevant->user_size -= size_change;

        } else {
            //Not much can be done

        }

        *errnoptr = 0;
        return ptr;

    } else {
        //Need to grow block.
        if(!next_node_adjacent) {
            //If the next node cannot be grown into, then do nothing
            *errnoptr = -1;
            return ptr;
        }
        //Get the size change
        size_change = size - relevant->size;
        if(after->size > size + sizeof(struct __myfs_memory_block_struct)) {
            //Next is large enough to exist after being expanded into
            new = (__myfs_memory_block_t) (((void *) relevant) + size);

            memcpy((void *) new,(void *)after, sizeof(struct __myfs_memory_block_struct));
            new->size -= size_change;
            new->user_size -= size_change;
            if(before == NULL) {
                handle->free_memory = __ptr_to_off(handle, new);
            } else {
                before->next = __ptr_to_off(handle, new);
            }

            relevant->size = size;
            relevant->user_size += size_change;

        } else if (after->size >= size_change) {
            //Absorb all of after
            //After is not large enough to be meaningful

            //Remove after from free memory
            if(before == NULL) {
                handle->free_memory = after->next;
            } else {
                before->next = after->next;
            }

            //Update sizes
            relevant->size += after->size;
            relevant->user_size += after->size;

        } else {
            //After is not large enough for the memory we need
            *errnoptr = -1;
            return ptr;
        }
        *errnoptr = 0;
        return ptr;
    }
}

/*	Attempts to reallocate memory so that the memory block with its data section beginning at ptr
		Can have a */
off_t __reallocate_mem_block(__myfs_handle_t handle, off_t ptr, size_t new_size, int *errnoptr){

    /* Declare variables */
    __myfs_memory_block_t relevant;
    __myfs_memory_block_t new_head;
    size_t old_dat_size, new_dat_size;
    off_t new_data;

    /* First, call resize */
    new_data = __resize_mem_block(handle, ptr, new_size, errnoptr);
    //Check if succeeded in resize
    if(*errnoptr == 0) {
        //If success, nothing else to do
        return ptr;
    }

    //get the old block
    relevant = (__myfs_memory_block_t) __off_to_ptr(handle, ptr - sizeof(struct __myfs_memory_block_struct));

    /* Get a new block of memory that is the right size */
    new_data = __allocate_mem_block(handle, new_size);

    /* Test if properly allocated */
    if(new_data == ((off_t)0)) {
        *errnoptr = -1;
        return ptr;
    }

    /* Get the header of the newly allocated block */
    new_head = (__myfs_memory_block_t) (__off_to_ptr(handle, new_data - sizeof(struct __myfs_memory_block_struct)));

    old_dat_size = relevant->size - sizeof(struct __myfs_memory_block_struct);
    new_dat_size = new_head->size - sizeof(struct __myfs_memory_block_struct);

    if (old_dat_size < new_dat_size) {
        memcpy(__off_to_ptr(handle,new_data), __off_to_ptr(handle, ptr), old_dat_size);
    } else {
        memcpy(__off_to_ptr(handle,new_data), __off_to_ptr(handle, ptr), new_dat_size);
    }

		__free_mem_block(handle, ptr);

    *errnoptr = 0;
    return new_data;
}

void __set_curr_time(__myfs_inode_t *node, int set_mod) {
    struct timespec ts;
    if(node == NULL) return;
    if(clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        node->times[0] = ts;
        if(set_mod) {
            node->times[1] = ts;
        }
    }
}


__myfs_handle_t __myfs_get_handle(void *fsptr, size_t fssize) {
    __myfs_handle_t handle;

    handle = (__myfs_handle_t) fsptr;
    // Check if magic is correct and if so, then return the handle
    if(handle->magic == MYFS_MAGIC) return handle;

    //If we're here, the file system needs to be initialized.

    /* Do variable declarations here, so we aren't doing declarations at the top
    when they won't be necessary in the majority of cases. */
    __myfs_inode_t *root;
    size_t mem_size;
    __myfs_memory_block_t first_block;
    off_t *root_children;

    /* Need to track size of all available memory for the purpose of
         properly setting up the block system. */
    mem_size = fssize;
    handle->size = fssize;
    //Exclude the handle:
    mem_size -= sizeof(struct __myfs_handle_struct);


    /* Set up root directory.
         Root dir will be set in stone as right after the handle */
    root = (__myfs_inode_t *)(fsptr + sizeof(struct __myfs_handle_struct));
    //Set type
    root->type = DIRECTORY;
    //Set name
    strcpy((char *) &root->name, "root");
    //Setup Timespec
    __set_curr_time(root, 1);
    //Set up directory stats a bit.
    root->value.directory.number_children=2;

    //Set up allocated children
    root->value.directory.allocated_children=2;

    //Mark this memory as taken
    mem_size -= sizeof(__myfs_inode_t);

    //Set the root directory in the handle
    handle->root_dir = __ptr_to_off(handle, root);

    /* Set up the allocateable memory blocks. */
    //Set first_block to be after the handle and the root directory.
    first_block = (__myfs_memory_block_t) (fsptr + sizeof(struct __myfs_handle_struct) + sizeof(__myfs_inode_t));
    first_block->next = 0;
    first_block->size = mem_size;
    first_block->user_size = mem_size - sizeof(struct __myfs_handle_struct);

    //Set the free_memory in the handle
    handle->free_memory = __ptr_to_off(handle, first_block);
    //Finished with memory initialization

    //Allocate memory for the children array in the root.
    root->value.directory.children = __allocate_mem_block(handle, 2* sizeof(off_t));
    root_children = __off_to_ptr(handle, root->value.directory.children);
    //Set the . subdirectory to be a self reference.
    root_children[0] = __ptr_to_off(handle, root);
    //Since it is the root, should have no ..
    root_children[1] = (off_t) 0;

    //Set handle's magic last in case something goes wrong during initialization
    handle->magic = MYFS_MAGIC;
    return handle;
}



__myfs_inode_t * __myfs_path_resolve(__myfs_handle_t handle, const char *path,int *errnoptr){
    char *token;
    int isFound=0;
    __myfs_inode_t *curr;
    size_t pathlen;
    char *path_cpy;

    if(path == NULL) {
        *errnoptr = EFAULT;
        return NULL;
    }

    if (path[0] != '/') {
        *errnoptr = EFAULT;
        return NULL;
    }

    if(strlen(path) > MYFS_STATIC_PATH_BUF_SIZE) {
        *errnoptr = ENAMETOOLONG;
        return NULL;
    }
    __myfs_inode_t *root = (__myfs_inode_t *) __off_to_ptr(handle,handle->root_dir);

    off_t *children = (off_t *) __off_to_ptr(handle,root->value.directory.children);

    size_t number_children = root->value.directory.number_children;

    if (!strcmp("/",path)){
        return root;
    }
    //Get length of path string to be passed to malloc
    //Add 1 to reinclude the null terminator
    pathlen = strlen(path) + (size_t)1;
    path_cpy = (char *) malloc(pathlen * sizeof(char));
    strcpy(path_cpy,path);

    token = strtok(path_cpy, "/");

    curr=root;
    while(token != NULL)
    {
        //Shortcut to avoid leaving filesystem
        //Check if we are trying to go up from the root.
        //Return NULL in the off chance that that happens.
        if(curr == root && strcmp("..",token) == 0) {
            free(path_cpy);
            *errnoptr = EACCES;
            return NULL;
        }
        //Reset found condition
        isFound=0;

        //Special case: .
        //Index 0 in children array
        //Burn the . token and restart the big loop.
        //No need to change curr or array bounds.
        if(strcmp(".",token) == 0) {
            isFound = 1;
            token = strtok(NULL, "/");
            continue;
        }

        //Special case: ..
        //Index 1 in children array
        /*
            I need to move up and
            reset the bounds of iteration
        */
        if(strcmp("..",token) == 0) {
            isFound = 1;

            //Move curr
            curr = (__myfs_inode_t *) __off_to_ptr(handle, children[1]);
            //Get the next number_children
            number_children = curr->value.directory.number_children;
            //Get the next children array
            children = (off_t *) __off_to_ptr(handle,curr->value.directory.children);
            //Burn token
            token = strtok(NULL, "/");

            continue;
        }

        /* j iterates throught the children array.
             Starts at 2 to skip the relative entries
        */
        for (size_t j = (size_t) 2; j < number_children; j++) {
            /*
                This conditional is a doozy
                Access the children array at index j.
                children[j] -> (off_t)

                Converts that offset to a pointer using __off_to_ptr
                (off_t) -> (void *)

                Casts that to an inode pointer
                (void *) -> (__myfs_inode_t *)

                Accesses the name field of the struct at that pointer.

                Uses strcmp to compare to the string, token and checks if they are equal using the == 0.

                If they are a match, then it executes the code in the if statement.
                Else, continue to the next value of j.
            */
            if(strcmp( token,((__myfs_inode_t *) __off_to_ptr(handle, children[j]))->name) == 0){
                /*
                    If inside here, found the correct part of the path, prepare to continue the search
                */

                //Get next token
                token = strtok(NULL, "/");
                //Move curr down to the child of interest
                curr= (__myfs_inode_t *) __off_to_ptr(handle, children[j]);
                //Check if curr is a directory
                if(curr->type == DIRECTORY) {
                    //If so prepare array to loop over and bounds of looping
                    //Get the next number_children
                    number_children = curr->value.directory.number_children;
                    //Get the next children array
                    children = (off_t *) __off_to_ptr(handle,curr->value.directory.children);
                }
                    //Else, curr is a file
                else {
                    //Get next token to check if curr is the last
                    //If curr is the last part of the path, then token will be NULL
                    token = strtok(NULL, "/");
                    //If it isn't NULL, then there is still more to path and curr shouldn't be searched as a dir.
                    if(token != NULL){
                        free(path_cpy);
                        *errnoptr = ENOTDIR;
                        return NULL;
                    }
                }
                //If the next part is found, then leave the for loop and set found condition to 1.
                isFound=1;
                break;
            }
        }
        //Check found condition
        if (isFound == 0){
            free(path_cpy);
            *errnoptr = ENOENT;
            return NULL;
        }
    }
    free(path_cpy);
    return curr;
}

/*
		This function truncates the last term off the end of a path
		This is useful for finding a directory to add a file into

		REMEMBER TO FREE THE STRING THIS FUNCTION RETURNS WHEN
		YOU ARE DONE WITH IT.

		RETURN: a char array of the appropriate size that has been
		allocated with malloc/calloc and contains the path with the
		last term removed

		NULL if root directory
*/

char * __remove_end_of_path(const char *path) {
    //Short circuit error check if root dir
    if(!strcmp(path, "/")) return NULL;
    //If path does not begin with /, then it is not a valid filepath.
    if(path[0] != '/') return NULL;

    /* Declare needed variables */
    char *modifiable_path; //Can be destroyed/modified without messing up the path
    char *path_to_ret; //Path that will be returned.  Will be null-terminated and just large enough
    size_t path_length; //Length of the original path for use in iterating backwards
    size_t iter;  //Used to iterate backwards
    size_t new_length; //Length of the truncated path

    //define path_length
    path_length = strlen(path);
    //define and fill modifiable_path
    //Needs to be one longer than the path because strlen does not include the null-terminator
    modifiable_path = (char *) malloc((path_length + (size_t) 1) * sizeof(char));
    if(modifiable_path == NULL) return NULL;
    strcpy(modifiable_path,path);

    //Get rid of / at the end of the path if there is one
    if(modifiable_path[path_length - (size_t) 1] == '/'){
        modifiable_path[path_length - (size_t) 1] = '\0';
    }

    //Iterate backwards through the string until a / is encountered
    //Additionally, set all characters between the end of the path and the last '/' to '\0'
    //path is guaranteed to at least start with '/'
    for(iter = path_length; modifiable_path[iter] != '/'; iter --){
        modifiable_path[iter] = '\0';
    }

    //Get new length
    new_length = strlen(modifiable_path);

    //Allocate memory for new path
    path_to_ret = (char *) malloc((new_length + (size_t) 1) * sizeof(char));

    //Error check
    if (path_to_ret == NULL) {
        free(modifiable_path);
        return NULL;
    }

    strcpy(path_to_ret, modifiable_path);

    //Free memory
    free(modifiable_path);
    return path_to_ret;
}

/* Gets the parent of the node at path */
__myfs_inode_t *__get_parent(__myfs_handle_t handle, const char *path, int *errnoptr) {
	/* Declare variables */
	char *parent_path = __remove_end_of_path(path);
	__myfs_inode_t *parentNode;
	parentNode = __myfs_path_resolve(handle,parent_path,errnoptr);
  free(parent_path);
	return parentNode;
}

char *__get_name(const char *path){
    //Vars
    size_t path_length;
    size_t name_len;
    char *str_to_ret;
    char *modifiable_path;
    char *delim_of_end;
    //define path_length
    path_length = strlen(path);
    //define and fill modifiable_path
    //Needs to be one longer than the path because strlen does not include the null-terminator
    modifiable_path = (char *) malloc((path_length + (size_t) 1) * sizeof(char));
    if(modifiable_path == NULL) return NULL;
    strcpy(modifiable_path,path);

    //Get rid of / at the end of the path if there is one
    if(modifiable_path[path_length - (size_t) 1] == '/'){
        modifiable_path[path_length - (size_t) 1] = '\0';
    }

    delim_of_end = strrchr(path, '/');
    delim_of_end ++;

    name_len = strlen(delim_of_end)+((size_t)1);

    //Allocate memory for new path
    str_to_ret = (char *) malloc((name_len) * sizeof(char));
    //Error check
    if (str_to_ret == NULL) {
        free(modifiable_path);
        return NULL;
    }

    strcpy(str_to_ret, delim_of_end);

    free(modifiable_path);
    return str_to_ret;
}
/* End of helper functions */

/* Implements an emulation of the stat system call on the filesystem
   of size fssize pointed to by fsptr.

   If path can be followed and describes a file or directory
   that exists and is accessable, the access information is
   put into stbuf.

   On success, 0 is returned. On failure, -1 is returned and
   the appropriate error code is put into *errnoptr.

   man 2 stat documents all possible error codes and gives more detail
   on what fields of stbuf need to be filled in. Essentially, only the
   following fields need to be supported:

   st_uid      the value passed in argument
   st_gid      the value passed in argument
   st_mode     (as fixed values S_IFDIR | 0755 for directories,
                                S_IFREG | 0755 for files)
   st_nlink    (as many as there are subdirectories (not files) for directories
                (including . and ..),
                1 for files)
   st_size     (supported only for files, where it is the real file size)
   st_atim
   st_mtim

*/
int __myfs_getattr_implem(void *fsptr, size_t fssize, int *errnoptr,
                          uid_t uid, gid_t gid,
                          const char *path, struct stat *stbuf) {
    __myfs_handle_t handle;
    __myfs_inode_t *node;


    handle = __myfs_get_handle(fsptr, fssize);

    if (handle == NULL){
        *errnoptr = EFAULT;
        return -1;
    }


    node = __myfs_path_resolve(handle,path,errnoptr);

    if (node == NULL){
        *errnoptr = ENOENT;
        return -1;
    }

    stbuf->st_uid=uid;
    stbuf->st_gid=gid;
    if (node->type == DIRECTORY){
        stbuf->st_mode = S_IFDIR | 0755;
        __myfs_inode_t *children = (__myfs_inode_t *) __off_to_ptr(handle,node->value.directory.children);
        int counter = 0;
        for (size_t i = (size_t) 0; i < node->value.directory.number_children; i++){
            if(children[i].type == DIRECTORY){
                counter++;
            }
        }
        stbuf->st_nlink = counter;
    }

    else if (node->type == REG_FILE){
        stbuf->st_mode = S_IFREG | 0755;
        stbuf->st_size = node->value.file.size;
        stbuf->st_nlink = 1;
    }
    stbuf->st_atim = node->times[0];
    stbuf->st_mtim = node->times[1];
    return 0;
}

/* Implements an emulation of the readdir system call on the filesystem
   of size fssize pointed to by fsptr.

   If path can be followed and describes a directory that exists and
   is accessable, the names of the subdirectories and files
   contained in that directory are output into *namesptr. The . and ..
   directories must not be included in that listing.

   If it needs to output file and subdirectory names, the function
   starts by allocating (with calloc) an array of pointers to
   characters of the right size (n entries for n names). Sets
   *namesptr to that pointer. It then goes over all entries
   in that array and allocates, for each of them an array of
   characters of the right size (to hold the i-th name, together
   with the appropriate '\0' terminator). It puts the pointer
   into that i-th array entry and fills the allocated array
   of characters with the appropriate name. The calling function
   will call free on each of the entries of *namesptr and
   on *namesptr.

   The function returns the number of names that have been
   put into namesptr.

   If no name needs to be reported because the directory does
   not contain any file or subdirectory besides . and .., 0 is
   returned and no allocation takes place.

   On failure, -1 is returned and the *errnoptr is set to
   the appropriate error code.

   The error codes are documented in man 2 readdir.

   In the case memory allocation with malloc/calloc fails, failure is
   indicated by returning -1 and setting *errnoptr to EINVAL.

*/
int __myfs_readdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                          const char *path, char ***namesptr) {
    /* Variable declarations */
    __myfs_handle_t handle; //File system handle
    __myfs_inode_t *dir_to_read; //Directory at path
    int number_to_report; //Number to return
    int alloc_fail = 0; //Set to one if a malloc fails
    char **name_list; //List of names to be inserted into *namesptr
    int num_successfully_allocated = 0;  //Used to track how many strings have been successfully allocated for deallocating
    int iter; //Number used to iterate through the children.
    off_t *children_array; //Array of the offsets of the children
    __myfs_inode_t *curr_child; // Used for convenient access to the child node being accessed
    size_t namelen; //Used as a convenient way to access the length of the string to be allocated.

    /* First get handle or initialize filesystem */
    handle = __myfs_get_handle(fsptr, fssize);

    /* Get the directory node from path */
    dir_to_read = __myfs_path_resolve(handle, path,errnoptr);

    /* Check if ptr is null, if so return -1 and set errno.
        If it is null, path is not a valid path. */
    if(dir_to_read == NULL) {
        return -1;
    }
    /* Check if node is a file and not a directory
         If it is, set errno and return -1 */
    if(dir_to_read->type == REG_FILE) {
        return -1;
    }

    /* Edge case: empty directory.  If this is the case, then dir_to_read ->value.directory.number_chlidern == 2.
         If this is the case, then simply return 0 without iteration.*/
    if(dir_to_read->value.directory.number_children == 2) {
        return 0;
    }

    /* Regular operation */
    //Set number that should be reported assuming allocation goes properly.
    //Should be two less than the number of children because . and .. are chlidren that should not be counted by readdir.
    number_to_report = dir_to_read->value.directory.number_children - 2;

    //Allocate name_list
    name_list = (char **) calloc(number_to_report, sizeof(char *));

    //Error check if calloc failed
    if(name_list == NULL) {
        *errnoptr = EINVAL;
        return -1;
    }

    //Set children_array
    children_array = (off_t *) __off_to_ptr(handle, dir_to_read->value.directory.children);

    for(iter = 0; iter < number_to_report; iter++) {
        //Get child at iter + 2
        curr_child = __off_to_ptr(handle, children_array[iter+2]);
        //Get size to allocate
        //Get length of string using strlen and add 1 for the null termination
        namelen = strlen(curr_child->name)+1;
        //Allocate memory for the name
        name_list[iter] = (char *) malloc(namelen * sizeof(char));

        //Check to see if the malloc succeeded or failed
        if(name_list[iter] == NULL) {
            alloc_fail = 1;
            break;
        }
        // Else increment num_successfully_allocated
        num_successfully_allocated++;
        //Copy name into name_list
        //strcpy includes the null termination
        strcpy(name_list[iter], curr_child->name);
    }

    //Check if malloc failed
    if(alloc_fail) {
        //Deallocate everything if malloc failed

        //Reuse iter here for convenience
        //Iterate to num_successfully_allocated to only free the strings that were allocated
        for(iter = 0; iter < num_successfully_allocated; iter++) {
            free(name_list[iter]);
        }
        //Deallocate name_list after all members have been deallocated
        free(name_list);
        //Set errno
        *errnoptr = EINVAL;
        return -1;
    }

    //If all goes right, set *namesptr to the filled name_list
    *namesptr = name_list;
    return number_to_report;
}

/* Implements an emulation of the mknod system call for regular files
   on the filesystem of size fssize pointed to by fsptr.

   This function is called only for the creation of regular files.

   If a file gets created, it is of size zero and has default
   ownership and mode bits.

   The call creates the file indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mknod.

*/
int __myfs_mknod_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
    /* STUB */
    *errnoptr = 0;
    __myfs_handle_t handle;
    __myfs_inode_t *parentNode; //Directory at path
    __myfs_inode_t *childNode;
    __myfs_file_block_t *fblock;
    off_t *children;
    off_t  allocate_inode;
    off_t allocate_fblock;
    int allocation_error = 0;
    int allocated_children;
    char *child_name = __get_name(path);
    char *parent_path = __remove_end_of_path(path); //parent path
    handle = __myfs_get_handle(fsptr, fssize);

    if(strlen(child_name)+1 > MYFS_MAXIMUM_NAME_LENGTH){
        *errnoptr = ENAMETOOLONG; //If Name is too long send correct error
        free(child_name);
        free(parent_path);
        return -1;
    }

    parentNode = __myfs_path_resolve(handle,parent_path,errnoptr);
    free(parent_path);
    //Error handling in path resolve...
    if (parentNode == NULL){
        free(child_name);
        return -1;
    }

    allocated_children = parentNode->value.directory.allocated_children;

    if(parentNode->value.directory.number_children+1 > allocated_children){
        parentNode->value.directory.children=
                __reallocate_mem_block(handle, parentNode->value.directory.children, allocated_children * 2 * sizeof(off_t *), &allocation_error);

        if(allocation_error < 0){
            free(child_name);
            *errnoptr = ENOSPC;
            return -1;
        }

        parentNode->value.directory.allocated_children*=2;
    }

    children = __off_to_ptr(handle, parentNode->value.directory.children);
    //allocate mem for child node
    allocate_inode = __allocate_mem_block(handle,sizeof(__myfs_inode_t));

    if (allocate_inode == (off_t)0){
        free(child_name);
        *errnoptr=ENOSPC;
        return -1;
    }

    allocate_fblock = __allocate_mem_block(handle,sizeof(__myfs_file_block_t));
    if (allocate_fblock == (off_t)0){
        free(child_name);
        *errnoptr=ENOSPC;
        return -1;
    }

    //Create Child Node
    childNode = (__myfs_inode_t *) __off_to_ptr(handle,allocate_inode);
    childNode->type = REG_FILE;
    strcpy((char *)&(childNode->name),child_name);
    free(child_name);
    __set_curr_time(childNode,1);
    childNode->value.file.size=(size_t)0;
    childNode->value.file.first_block = allocate_fblock;
    fblock = (__myfs_file_block_t *) __off_to_ptr(handle,allocate_fblock);
    fblock->size = (size_t) 0;
    fblock->next = (off_t) 0;
    fblock->allocated = (size_t) 0;
    fblock->data = (off_t) 0;

    children[parentNode->value.directory.number_children] = allocate_inode;
    //Increase amount of children :D
    parentNode->value.directory.number_children++;
    return 0;
}

/* Implements an emulation of the unlink system call for regular files
   on the filesystem of size fssize pointed to by fsptr.

   This function is called only for the deletion of regular files.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 unlink.

*/
int __myfs_unlink_implem(void *fsptr, size_t fssize, int *errnoptr,
                         const char *path) {
	/* Declare variables */
	__myfs_file_block_t *curr_fblock, *prev_fblock; //Will be used to iterate accross the file and free the file blocks
	__myfs_inode_t *parent_dir; //Parent directory
	__myfs_inode_t *f_to_unlink; //File to be unlinked located at path.
	__myfs_handle_t handle; //Handle of the file system
	off_t *parent_contents; //Used for convenient looping
	off_t file_off_set; //Used to free the directory's memory
	size_t i;
	/* Check the length of the path string */
	if(strlen(path) > MYFS_STATIC_PATH_BUF_SIZE) {
		*errnoptr = ENAMETOOLONG;
		return -1;
	}
	
	handle = __myfs_get_handle(fsptr, fssize);
		
	/* Get parent dir */
	parent_dir = __get_parent(handle, path, errnoptr);
	
	/* Check for error in getting ptr */
	if(parent_dir == NULL) {
		return -1;
	}
	parent_contents = (off_t *) __off_to_ptr(handle, parent_dir->value.directory.children);
	
	/* Get the relevant file */
	f_to_unlink = __myfs_path_resolve(handle, path, errnoptr);
	
	/* Check for errors in getting file ptr */
	if(f_to_unlink == NULL) {
		return -1;
	}
	file_off_set = __ptr_to_off(handle, f_to_unlink);
	
	/* Set iterator pointers for the file block systems */
	prev_fblock = NULL;
	curr_fblock = (__myfs_file_block_t *) __off_to_ptr(handle, f_to_unlink->value.file.first_block);
	
	/* This loop iterates through the block linked list frees each one and the associated data. */
	while(curr_fblock != NULL) {
		//Free the file block's data
		if(curr_fblock-> data != 0) {
			__free_mem_block(handle, curr_fblock->data);
		}
		//Free the previous block if it is not NULL
		if(prev_fblock != NULL) {
			__free_mem_block(handle, __ptr_to_off(handle, prev_fblock));
		}
		
		//Increment prev_fblock
		prev_fblock = curr_fblock;
		
		//Increment curr_fblock
		curr_fblock = __off_to_ptr(handle, curr_fblock->next);
	}
	// When curr falls out of the loop, the last node will not have been freed
	__free_mem_block(handle, __ptr_to_off(handle, prev_fblock));
	
	//Free the file inode from memory.
	__free_mem_block(handle, file_off_set);
	
	//Remove file from parent's array
	for(i = 0; i < parent_dir->value.directory.number_children; i++) {
		if (parent_contents[i] == file_off_set) {
			parent_contents[i] = ((off_t)0);
			break;
		}
	}
	//Shifts back parent array so there are no gaps
	i++;
	while(i < parent_dir->value.directory.number_children) {
		parent_contents[i-1] = parent_contents[i];
		i++;
	}

	//Decrement the number of children in the parent directory
	parent_dir->value.directory.number_children--;

	return 0;
}

/* Implements an emulation of the rmdir system call on the filesystem
   of size fssize pointed to by fsptr.

   The call deletes the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The function call must fail when the directory indicated by path is
   not empty (if there are files or subdirectories other than . and ..).

   The error codes are documented in man 2 rmdir.

*/
int __myfs_rmdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
    /* Declare variables */
		__myfs_handle_t handle;
		__myfs_inode_t *dir_node;
		__myfs_inode_t *parent_dir;
		off_t *parent_contents; //Used for convenient looping
		off_t dir_off_set; //Used to free the directory's memory
		int i;
		
		if(strlen(path) > MYFS_STATIC_PATH_BUF_SIZE) {
			*errnoptr = ENAMETOOLONG;
			return -1;
		}
		
		
		/* Get handle */
		handle = __myfs_get_handle(fsptr, fssize);
		
		//Get parent dir
		parent_dir = __get_parent(handle, path, errnoptr);
		if(parent_dir == NULL) {
			return -1;
		}
		parent_contents = (off_t *) __off_to_ptr(handle, parent_dir->value.directory.children);
		
		//Get directory to remove
		dir_node = __myfs_path_resolve(handle, path, errnoptr);
		if(dir_node == NULL) {
			return -1;
		}
		dir_off_set = __ptr_to_off(handle, dir_node);
		
		
		if(dir_node->value.directory.number_children != 2) {
			*errnoptr = ENOTEMPTY;
			return -1;
		}
		
		//Free memory that the child array occupies
		__free_mem_block(handle, dir_node->value.directory.children);
		
		//Remove directory from parent's array
		for(i = 0; i < parent_dir->value.directory.number_children; i++) {
			if (parent_contents[i] == dir_off_set) {
				parent_contents[i] = ((off_t)0);
				break;
			}
		}
		//Shifts back parent array so there are no gaps
		i++;
		while(i < parent_dir->value.directory.number_children) {
			parent_contents[i-1] = parent_contents[i];
			i++;
		}
		//Decrements number of parent's children
        parent_dir->value.directory.number_children--;
		
		//Free memory taken by directory's inode
		__free_mem_block(handle, dir_off_set);
		
		
    return 0;
}

/* Implements an emulation of the mkdir system call on the filesystem
   of size fssize pointed to by fsptr.

   The call creates the directory indicated by path.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 mkdir.

*/
int __myfs_mkdir_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path) {
    *errnoptr = 0;
    __myfs_handle_t handle;
    __myfs_inode_t *parentNode; //Directory at path
    __myfs_inode_t *childNode;
    off_t *children;
    off_t *child_children;
    off_t  allocate_inode;
    off_t allocate_fblock;
    int allocation_error = 0;
    int allocated_children;
    char *child_name = __get_name(path);
    char *parent_path = __remove_end_of_path(path); //parent path
    handle = __myfs_get_handle(fsptr, fssize);

    if(strlen(child_name)+1 > MYFS_MAXIMUM_NAME_LENGTH){
        *errnoptr = ENAMETOOLONG; //If Name is too long send correct error
        free(child_name);
        free(parent_path);
        return -1;
    }

    parentNode = __myfs_path_resolve(handle,parent_path,errnoptr);
    free(parent_path);
    //Error handling in path resolve...
    if (parentNode == NULL){
        free(child_name);
        return -1;
    }

    allocated_children = parentNode->value.directory.allocated_children;

    if(parentNode->value.directory.number_children+1 > allocated_children){
        parentNode->value.directory.children=
                __reallocate_mem_block(handle, parentNode->value.directory.children, allocated_children * 2 * sizeof(off_t *), &allocation_error);

        if(allocation_error < 0){
            free(child_name);
            *errnoptr = ENOSPC;
            return -1;
        }

        parentNode->value.directory.allocated_children*=2;
    }

    children = __off_to_ptr(handle, parentNode->value.directory.children);
    //allocate mem for child node
    allocate_inode = __allocate_mem_block(handle,sizeof(__myfs_inode_t));

    if (allocate_inode == (off_t)0){
        free(child_name);
        *errnoptr=ENOSPC;
        return -1;
    }

    allocate_fblock = __allocate_mem_block(handle, 2* sizeof(off_t));
    if (allocate_fblock == (off_t)0){
        free(child_name);
        *errnoptr=ENOSPC;
        return -1;
    }

    //Create Child Node
    childNode = (__myfs_inode_t *) __off_to_ptr(handle,allocate_inode);
    //Set Type
    childNode->type = DIRECTORY;
    //Set Name
    strcpy((char *)&(childNode->name),child_name);
    //Free prev name
    free(child_name);
    //Set curr time
    __set_curr_time(childNode,1);
    //Set up directory stats a bit.
    childNode->value.directory.number_children=2;
    //Set up allocated Children
    childNode->value.directory.allocated_children=2;
    childNode->value.directory.children = allocate_fblock;
    child_children = __off_to_ptr(handle,childNode->value.directory.children);
    child_children[0] = __ptr_to_off(handle,childNode);
    child_children[1] = __ptr_to_off(handle,parentNode);

    children[parentNode->value.directory.number_children] = allocate_inode;
    //Increase amount of children :D
    parentNode->value.directory.number_children++;
    return 0;
}

/* Implements an emulation of the rename system call on the filesystem
   of size fssize pointed to by fsptr.

   The call moves the file or directory indicated by from to to.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   Caution: the function does more than what is hinted to by its name.
   In cases the from and to paths differ, the file is moved out of
   the from path and added to the to path.

   The error codes are documented in man 2 rename.

*/
int __myfs_rename_implem(void *fsptr, size_t fssize, int *errnoptr,
                         const char *from, const char *to) {
    /* STUB */
    return -1;
}

/* Implements an emulation of the truncate system call on the filesystem
   of size fssize pointed to by fsptr.

   The call changes the size of the file indicated by path to offset
   bytes.

   When the file becomes smaller due to the call, the extending bytes are
   removed. When it becomes larger, zeros are appended.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 truncate.

*/
int __myfs_truncate_implem(void *fsptr, size_t fssize, int *errnoptr,
                           const char *path, off_t offset) {
    /* STUB */
    return -1;
}

/* Implements an emulation of the open system call on the filesystem
   of size fssize pointed to by fsptr, without actually performing the opening
   of the file (no file descriptor is returned).

   The call just checks if the file (or directory) indicated by path
   can be accessed, i.e. if the path can be followed to an existing
   object for which the access rights are granted.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The two only interesting error codes are

   * EFAULT: the filesystem is in a bad state, we can't do anything

   * ENOENT: the file that we are supposed to open doesn't exist (or a
             subpath).

   It is possible to restrict ourselves to only these two error
   conditions. It is also possible to implement more detailed error
   condition answers.

   The error codes are documented in man 2 open.

*/
int __myfs_open_implem(void *fsptr, size_t fssize, int *errnoptr,
                       const char *path) {
    uid_t uid = (uid_t)0;
    gid_t gid = (gid_t)0;
    struct stat stbuf;
    return __myfs_getattr_implem(fsptr, fssize, errnoptr, uid, gid, path, &stbuf);
}

/* Implements an emulation of the read system call on the filesystem
   of size fssize pointed to by fsptr.

   The call copies up to size bytes from the file indicated by
   path into the buffer, starting to read at offset. See the man page
   for read for the details when offset is beyond the end of the file etc.

   On success, the appropriate number of bytes read into the buffer is
   returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 read.

*/
int __myfs_read_implem(void *fsptr, size_t fssize, int *errnoptr,
                       const char *path, char *buf, size_t size, off_t offset) {
    /* STUB */
    return -1;
}

/* Implements an emulation of the write system call on the filesystem
   of size fssize pointed to by fsptr.

   The call copies up to size bytes to the file indicated by
   path into the buffer, starting to write at offset. See the man page
   for write for the details when offset is beyond the end of the file etc.

   On success, the appropriate number of bytes written into the file is
   returned. The value zero is returned on an end-of-file condition.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 write.

*/
int __myfs_write_implem(void *fsptr, size_t fssize, int *errnoptr,
                        const char *path, const char *buf, size_t size, off_t offset) {
    /* STUB */
    return -1;
}

/* Implements an emulation of the utimensat system call on the filesystem
   of size fssize pointed to by fsptr.

   The call changes the access and modification times of the file
   or directory indicated by path to the values in ts.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 utimensat.

*/
int __myfs_utimens_implem(void *fsptr, size_t fssize, int *errnoptr,
                          const char *path, const struct timespec ts[2]) {
    /* Declare variables */
    __myfs_handle_t handle;
    handle = __myfs_get_handle(fsptr, fssize);

    __myfs_inode_t *node;
    if (path == NULL){
        *errnoptr = EINVAL;
        return -1;
    }

    if (strlen(path) > MYFS_STATIC_PATH_BUF_SIZE){
        *errnoptr = ENAMETOOLONG;
        return -1;
    }

    node = __myfs_path_resolve(handle,path,errnoptr);
    //Error handling done in myfspathresolve
    if (node == NULL){
        return -1;
    }

    node->times[0]=ts[0];
    node->times[1]=ts[1];


    return 0;
}

/* Implements an emulation of the statfs system call on the filesystem
   of size fssize pointed to by fsptr.

   The call gets information of the filesystem usage and puts in
   into stbuf.

   On success, 0 is returned.

   On failure, -1 is returned and *errnoptr is set appropriately.

   The error codes are documented in man 2 statfs.

   Essentially, only the following fields of struct statvfs need to be
   supported:

   f_bsize   fill with what you call a block (typically 1024 bytes)
   f_blocks  fill with the total number of blocks in the filesystem
   f_bfree   fill with the free number of blocks in the filesystem
   f_bavail  fill with same value as f_bfree
   f_namemax fill with your maximum file/directory name, if your
             filesystem has such a maximum

*/
int __myfs_statfs_implem(void *fsptr, size_t fssize, int *errnoptr,
                         struct statvfs* stbuf) {
    /* STUB */
    return -1;
}
