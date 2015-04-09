PodArch : Protecting Legacy Applications with a Purely Hardware TCB
===================================================================


System Requirements
-------------------
To compile PodArch on your system, you will need the following:
* 2.5GHz CPU with minimum 2GB RAM (4GB Preferred)
* Standard C++ compiler, like g++ or icc
* SCons tool for compiling PodArch (Minimum version 1.2.0)
* SDL Development Libraries (Required for QEMU)


Compiling
---------
If you don't have SCons install, install it using your standard application
installation program like apt-get or yum.

Once you have SCons install go to PodArch-Marss directory and give following command:

    $ scons -Q config=./podarch.conf

Default compile disables debugging and logging functionalities, to compile with
logging functions enabled, give following command:

    $ scons -Q debug=1 config=./podarch.conf

Note that the default compile process compiles PodArch for single-core configuration. As of now, this implementation of PodArch can only support single-core configuration.

To clean your compilation:

    $ scons -Q -c

Running
-------
Make sure:
	 1. you have compiled the PodArch-compatible linux kernel given in the repository and obtained the bzImage file
	 2. you have a proper pod executable you wish to run in the disk image that you'll use for PodArch

After successfull compilation, to run PodArch you have to be in the root of PodArch source directory.  Then give the following command:

	$ sudo qemu/qemu-system-x86_64 -m 2G -kernel ../linuxkernel/arch/x86/boot/bzImage -hda /path/to/disk/image/sid.ext2 -append "root=/dev/sda"

If you're using our disk image, here are the login details:
Username: root
Password: root

You can use all the regular QEMU command here, like start VM window in VNC give
'vnc :10' etc.  Once the system is booted, you can switch to Monitor mode using
'Ctrl-Alt-2' key and give following command to switch to simulation mode:

May the Pods be with you.
