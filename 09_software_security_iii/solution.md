# System Security - Exercixse 09

## Part 1 - Common Weaknesses


## Part 2 - Sanitizers

### Address Sanitizer
Below is the output of running the address.c program with and without the sanitizer:   

``` console
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./address AAAAAAAAAAAA BBBBBBBBBBBB
What's your name?
Felix
============== Moin Felix ==============
Do you like pointers?
meh
WTF???
munmap_chunk(): invalid pointer
Aborted (core dumped)
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./address_asan AAAAAAAAAAA BBBBBBBBBBB
What's your name?
felix
=================================================================
==139660==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x7f088f82457d bp 0x7fffd39a8270 sp 0x7fffd39a7a18
WRITE of size 5 at 0x602000000014 thread T0
    #0 0x7f088f82457c  (/lib/x86_64-linux-gnu/libasan.so.5+0x9b57c)
    #1 0x558a8604a6b6 in strcpy /usr/include/x86_64-linux-gnu/bits/string_fortified.h:90
    #2 0x558a8604a6b6 in hello /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address.c:21
    #3 0x558a8604a3b7 in main /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address.c:69
    #4 0x7f088f5be0b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #5 0x558a8604a4ad in _start (/home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address_asan+0x24ad)

0x602000000014 is located 0 bytes to the right of 4-byte region [0x602000000010,0x602000000014)
allocated by thread T0 here:
    #0 0x7f088f896bc8 in malloc (/lib/x86_64-linux-gnu/libasan.so.5+0x10dbc8)
    #1 0x558a8604a695 in hello /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address.c:19

SUMMARY: AddressSanitizer: heap-buffer-overflow (/lib/x86_64-linux-gnu/libasan.so.5+0x9b57c)
Shadow bytes around the buggy address:
  0x0c047fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c047fff8000: fa fa[04]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==139660==ABORTING
```  

Looking at the output from running with the sanitizer, it is clear that the code at line 21 copies out of bounds to a buffer allowcated at line 19:  
``` c
char* hello(char* greeting) {
    char name[33];
    printf("What's your name?\n");
    fgets(name, 33, stdin);
    for (size_t i = 0; i < 33; ++i) {
        if (name[i] == '\n') {
            name[i] = '\0';
        }
    }

    size_t l1 = strlen(greeting);
    size_t l2 = strlen(name);
    char* buf = malloc(l1);
    assert(buf != NULL);
    strcpy(buf, greeting);
    buf[l1] = ' ';
    strncat(buf + l1 + 1, name, 32);
    return buf;
}
```  
When looking at the program, this is clearly because the line ```buf[l1] = ' ';``` writes to the first byte after the buffer, since a buffer of length N has highest index N-1.
Correcting the error by increasing the buffer size by one (pretending not to see the next error), recompiling and running the program with the sanitizer then provides the following output:  
``` console
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ make
gcc -o address -g -O3 -w address.c
gcc -fsanitize=address -o address_asan -g -O3 -w address.c
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./address_asan AAAAAAAAAAA BBBBBBBBBBB
What's your name?
felix
============== (null) ==============
Do you like pointers?
meh
AddressSanitizer:DEADLYSIGNAL
=================================================================
==140243==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55aca317e3c0 bp 0x7fff7e498588 sp 0x7fff7e498480 T0)
==140243==The signal is caused by a READ memory access.
==140243==Hint: address points to the zero page.
    #0 0x55aca317e3bf in main /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address.c:75
    #1 0x7ff061fb50b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #2 0x55aca317e46d in _start (/home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address_asan+0x246d)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address.c:75 in main
==140243==ABORTING
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ make
gcc -o address -g -O3 -w address.c
gcc -fsanitize=address -o address_asan -g -O3 -w address.c
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./address_asan AAAAAAAAAAA BBBBBBBBBBB
What's your name?
felix
=================================================================
==140343==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000015 at pc 0x7f79f166617d bp 0x7ffd79c4c1a0 sp 0x7ffd79c4b948
WRITE of size 6 at 0x602000000015 thread T0
    #0 0x7f79f166617c in strncat (/lib/x86_64-linux-gnu/libasan.so.5+0xc717c)
    #1 0x55958e1c16f2 in strncat /usr/include/x86_64-linux-gnu/bits/string_fortified.h:136
    #2 0x55958e1c16f2 in hello /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address.c:23
    #3 0x55958e1c13b7 in main /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address.c:69
    #4 0x7f79f13d40b2 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x270b2)
    #5 0x55958e1c14ad in _start (/home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address_asan+0x24ad)

0x602000000015 is located 0 bytes to the right of 5-byte region [0x602000000010,0x602000000015)
allocated by thread T0 here:
    #0 0x7f79f16acbc8 in malloc (/lib/x86_64-linux-gnu/libasan.so.5+0x10dbc8)
    #1 0x55958e1c1699 in hello /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/address.c:19

SUMMARY: AddressSanitizer: heap-buffer-overflow (/lib/x86_64-linux-gnu/libasan.so.5+0xc717c) in strncat
Shadow bytes around the buggy address:
  0x0c047fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c047fff8000: fa fa[05]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==140343==ABORTING
```

Which then reveals the next error, where strncat copies the name into the buffer as well. The complete size necessary for the buffer is then corrected to 'l1 + l2 + 1'


### Thread sanitizer
Running the thread sanitizer on the provided program:  
``` console
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./thread_tsan 10000 40
thread_tsan
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./thread_tsan 10000 40
==================
WARNING: ThreadSanitizer: unlock of an unlocked mutex (or by a wrong thread) (pid=140836)
    #0 pthread_mutex_unlock ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors.inc:4179 (libtsan.so.0+0x3aadc)
    #1 main /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:61 (thread_tsan+0x13a1)

  Location is stack of main thread.

  Location is global '<null>' at 0x000000000000 ([stack]+0x00000001e1c0)

  Mutex M0 (0x7ffd16ed61c0) created at:
    #0 pthread_mutex_init ../../../../src/libsanitizer/tsan/tsan_interceptors_posix.cpp:1220 (libtsan.so.0+0x4a616)
    #1 main /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:60 (thread_tsan+0x1399)

SUMMARY: ThreadSanitizer: unlock of an unlocked mutex (or by a wrong thread) /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:61 in main
==================
==================
WARNING: ThreadSanitizer: data race (pid=140836)
  Read of size 8 at 0x7ffd16ed61b8 by thread T3:
    #0 thread_function /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:33 (thread_tsan+0x16e4)

  Previous write of size 8 at 0x7ffd16ed61b8 by thread T2 (mutexes: write M0):
    #0 thread_function /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:36 (thread_tsan+0x171e)

  Location is stack of main thread.

  Location is global '<null>' at 0x000000000000 ([stack]+0x00000001e1b8)

  Mutex M0 (0x7ffd16ed61c0) created at:
    #0 pthread_mutex_init ../../../../src/libsanitizer/tsan/tsan_interceptors_posix.cpp:1220 (libtsan.so.0+0x4a616)
    #1 main /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:60 (thread_tsan+0x1399)

  Thread T3 (tid=140840, running) created by main thread at:
    #0 pthread_create ../../../../src/libsanitizer/tsan/tsan_interceptors_posix.cpp:962 (libtsan.so.0+0x5ea79)
    #1 main /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:69 (thread_tsan+0x1428)

  Thread T2 (tid=140839, finished) created by main thread at:
    #0 pthread_create ../../../../src/libsanitizer/tsan/tsan_interceptors_posix.cpp:962 (libtsan.so.0+0x5ea79)
    #1 main /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:69 (thread_tsan+0x1428)

SUMMARY: ThreadSanitizer: data race /home/felix/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii/thread.c:33 in thread_function
==================
there are 1229 primes up to 10000
ThreadSanitizer: reported 2 warnings
```

This points out several weaknesses in the program, the first one being an unlock of an unlocked mutex:  
``` c
pthread_mutex_t mutex;
pthread_mutex_init(&mutex, NULL);
pthread_mutex_unlock(&mutex);
```  
Which is clear enough since the mutex is unlocked immediately after initialization.  

The second error is a potential data race between line 33 and 36:  
```c
void* thread_function(void* arg) {
    thread_arg_t* thread_arg = arg;
    for (long n = thread_arg->thread_id; n < thread_arg->max_number; n += thread_arg->num_threads) {
        if (is_prime(n)) {
            long num_primes = *thread_arg->num_primes;
            num_primes += 1;
            pthread_mutex_lock(thread_arg->mutex);
            *thread_arg->num_primes = num_primes;
            pthread_mutex_unlock(thread_arg->mutex);
        }
    }
    return NULL;
}
```

Here, both the read and the write should be inside the protected section. Correcting these two errors and running again, provides the following output:  
``` console
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ make clean
rm -f address address_asan thread thread_tsan undefined undefined_ubsan
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ make
gcc -o address -g -O3 -w address.c
gcc -fsanitize=address -o address_asan -g -O3 -w address.c
gcc -pthread -o thread -g -O3 -w thread.c
gcc -fsanitize=thread -pthread -o thread_tsan -g -O3 -w thread.c
gcc -o undefined -g -O3 -w undefined.c
gcc -fsanitize=undefined -o undefined_ubsan -g -O3 -w undefined.c
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./thread_tsan 10000 40
there are 1229 primes up to 10000
```
Leaving the code without any weaknesses the sanitizer can detect.

### UBSan
Looking at the undefined.c program, a bunch of misallignment errors are detected:  
``` console  
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./undefined 36 6
36
6
no overflow happened :)
42
success
p = 0x7ffe5cf96b11
s = 328350
felix@felix-laptop-20:~/courses/e21-syssec/au-syssec-e21-exercises/09_software_security_iii$ ./undefined_ubsan 36 6
36
6
no overflow happened :)
42
undefined.c:45:23: runtime error: load of misaligned address 0x7fffb11ca9d1 for type 'uint32_t', which requires 4 byte alignment
0x7fffb11ca9d1: note: pointer points here
 7f 00 00  00 00 00 00 00 01 00 00  00 02 00 00 00 03 00 00  00 04 00 00 00 05 00 00  00 06 00 00 00
              ^
undefined.c:45:33: runtime error: load of misaligned address 0x7fffb11ca9d1 for type 'uint32_t', which requires 4 byte alignment
0x7fffb11ca9d1: note: pointer points here
 7f 00 00  00 00 00 00 00 01 00 00  00 02 00 00 00 03 00 00  00 04 00 00 00 05 00 00  00 06 00 00 00
              ^
undefined.c:45:17: runtime error: store to misaligned address 0x7fffb11ca9d1 for type 'uint32_t', which requires 4 byte alignment
0x7fffb11ca9d1: note: pointer points here
 7f 00 00  00 00 00 00 00 01 00 00  00 02 00 00 00 03 00 00  00 04 00 00 00 05 00 00  00 06 00 00 00
              ^
success
p = 0x7fffb11ca9d1
undefined.c:35:15: runtime error: load of misaligned address 0x7fffb11ca9d1 for type 'uint32_t', which requires 4 byte alignment
0x7fffb11ca9d1: note: pointer points here
 7f 00 00  00 00 00 00 00 01 00 00  00 04 00 00 00 09 00 00  00 10 00 00 00 19 00 00  00 24 00 00 00
              ^
s = 328350
```  
