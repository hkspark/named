#Makes required directories to store shell, commands and libs needed for jail dir
mkdir /home/jbezos/lib
mkdir /home/jbezos/lib64
mkdir /home/jbezos/bin

#Copy the shell into jail and required libs for shell (needed for all whether commands or not)
cp /bin/sh /home/jbezos/bin/

#Can run ldd /bin/sh to make sure libs match
cp /lib/x86_64-linux-gnu/libc.so.6 /home/jbezos/lib/
cp /lib64/ld-linux-x86-64.so.2 /home/jbezos/lib/

#Copy command ls and required libs to jail (gives ls command to jail) (can check libs with ldd /bin/ls)
cp /bin/ls /home/jbezos/bin/
cp /lib/x86_64-linux-gnu/libselinux.so.1 /home/jbezos/lib
cp /lib/x86_64-linux-gnu/libc.so.6 /home/jbezos/lib
cp /lib/x86_64-linux-gnu/libpcre2-8.so.0 /home/jbezos/lib
cp /lib64/ld-linux-x86-64.so.2 /home/jbezos/lib64

#copy cat command and libs over
cp /bin/cat /home/jbezos/bin/
cp /lib/x86_64-linux-gnu/libc.so.6 /home/jbezos/lib
cp /lib64/ld-linux-x86-64.so.2 /home/jbezos/lib64

#Copy echo command and libs
cp /bin/echo /home/jbezos/bin/
cp /lib/x86_64-linux-gnu/libc.so.6 /home/jbezos/lib
cp /lib64/ld-linux-x86-64.so.2 /home/jbezos/lib64


