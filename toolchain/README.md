=====================================================
The Ultimate Hitchhikers Guide to making a Pod binary
=====================================================
Don't panic.
-----------------------------------------------------

Alice is a girl.
And she wants to say hello to the world (securely).

She knows C, and writes a program called hello-world.c.

She loves gcc, and PodArch loves statically-linked binary.

And therefore, Alice's terminal looks like this.

	$ gcc -o hello hello-world.c -static -T 1ld
	$ gcc -c -o hello.o hello-world.c 
	$ ./get_pod_intc -i hello -o some_hello -k key -c cpu > /dev/null
	$ ld -r -b binary -o pod_intc.o podintc 
	$ objcopy --rename-section .data=.pod_inc,alloc,load,readonly,data,contents pod_intc.o pod_intc.o
	$ gcc -o hello hello.o pod_intc.o -static -T 2ld
	
	$ ./makepod -i hello -o pod_hello -k key -c cpu > /dev/null

Alice then runs ./pod_hello on PodArch. So much win.
