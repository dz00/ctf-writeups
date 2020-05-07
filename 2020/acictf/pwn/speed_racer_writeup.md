# ACICTF 2020 - Speed Racer - 450 pt pwn

## The Binary

This is a multi-threaded race car management system. As the name and use of threads imply, there is likely a race condition

## The Flaws

In the add car function we see the following coutesy if IDA's decompiler:

```c
  new_racer = (Racer *)malloc(sizeof(Racer));
  if ( !new_racer )
  {
    close(sock);
    pthread_exit(0LL);
  }
  memset(new_racer, 0, sizeof(Racer));
  new_racer->car_name = (char *)malloc(car_name_size);
  if ( !new_racer )
  {
    close(sock);
    pthread_exit(0LL);
  }
  pthread_mutex_lock(&mutex);
  new_racer->next = racer_list;
  racer_list = new_racer;
  pthread_mutex_unlock(&mutex);                 // *** this is too early to unlock
  new_racer->passengers = passengers;
  new_racer->number = car_number;
  max_speed = get_max_speed(&_d_);
  new_racer->max_speed = max_speed;
  strncpy(new_racer->racer_name, racer_name, 0x10uLL);
  strncpy(new_racer->car_color, color, 0x10uLL);
  new_racer->car_name_size = car_name_size;
  read(sock, new_racer->car_name, car_name_size);// *** can get a use after free here by deleting this car in another thread
                                                 // It's also the case that we need not send `car_name_size` bytes
```

The problem above is that the mutex is released before they are done manipulating the new racer, so we can simply halt the thread that is adding the racer by delaying our send of the `car_name` field until after we have won the race.

To win the race, we create a second thread and delete the car that was added by the first thread, which among other things deletes the `car_name` buffer. Because the delete happens in a different thread, the deleted block (size 0x20) will be placed in the second threads tcache. When we finally send the car_name data we will overwrite the `next` pointer in the tcache'd chunk with the address of the `free` entry in the binary's GOT. Finally we allocate two new cars, each with 0x18 byte name fields. The first allocation consumes the head of the tcache list, and the second allocation returns a pointer to the binary's got and we can overwrite the pointer to `free` because the binary is NOT `FULL RELRO`.

To get a libc leak, we allocate a large name (0x800), then free it to the unsorted bin.  After getting the block allocated back to us, we also use the fact that short reads are allowed in order to not fully fill it so that we can preserve the chunks next pointer. We can then turn around and print the associated racer info to get the unsorted bin pointer leaked back to us.

With leak in hand, we drop a rop chain in the heap as a car name, overwrite the GOT entry for `free` with a pivot gadget from libc, and kick off the chain by freeing the block containing our rop chain: `dup2 -> dup2 -> dup2 -> system("/bin/sh")`
