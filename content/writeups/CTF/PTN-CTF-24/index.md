---
title: "Pentester Nepal's 2024 CTF Writeups"
date: 2024-09-03
description: Writeup for PTN CTF 2024 Organized By Hack@Sec in celebration of 11th Anniversary of Pentester Nepal 
summary: Writeup for PTN CTF 2024 Organized By Hack@Sec in celebration of 11th Anniversary of Pentester Nepal 
draft: false
Tags:
- CTF
---

Hello guys, this year PTN is hosting 24 hour CTF competition in celebration of 11th Anniversary. The CTF is styled in jeopardy mode. So I, rezydev is playing this CTF with NCA1@Nepal. 
Let's get into CTF writeup now.
## No one goes empty handed!
The CTF was supposed to be started at 3:00 PM NPT but we were supposed to register our team at 12:00 noon. So, I registered my team and was just looking around the website to read "CTF Competition Rules". I have a habit of highlighting the text i read on screen. All I did was highlighted the whole text and found few letters which were hidden.
![](Pasted%20image%2020240802132655.png)![](Pasted%20image%2020240802132756.png)
Since the color code `f7f7f7` is a very light shade of gray, few texts were hidden and I assembled all the hidden texts which gave me a flag: `PTNCTF24{sanity_check}`. And to be honest, I don't know if this is just there or what as the CTF wasn't started yet, but i can confirm it's part of OSINT. Nvm, it was for "No one goes empty handed!". Haha, so let's go.

I tried alot with OSINT & Web but no success, but for fun I tried reverse engineering.
## Reverse Engineering
### E-reverse
They gave us a file `PasswordChecker.class` which is a Java Class. I ran ghidra and put the file in it. This is the ghidra output:
```
#include "out.h"



// Flags:
//   ACC_PUBLIC
// 
// public PasswordChecker() 

void <init>_void(PasswordChecker this)

{
  this.<init>();
  return;
}



// Flags:
//   ACC_PUBLIC
//   ACC_STATIC
// 
// public static void main(java.lang.String[]) 

void main_java_lang_String___void(String[] param1)

{
  PrintStream pPVar1;
  String pSVar2;
  boolean bVar3;
  Scanner objectRef;
  
  objectRef = new Scanner(System_in);
  pPVar1 = System_out;
  pPVar1.print("Enter the password: ");
  pSVar2 = objectRef.nextLine();
  bVar3 = PasswordChecker_checkPassword(pSVar2);
  if (bVar3) {
    pPVar1 = System_out;
    pPVar1.println("Access granted!");
  }
  else {
    pPVar1 = System_out;
    pPVar1.println("Access denied!");
  }
  objectRef.close();
  return;
}



// Flags:
//   ACC_PRIVATE
//   ACC_STATIC
// 
// private static boolean checkPassword(java.lang.String) 

boolean checkPassword_java_lang_String_boolean(String param1)

{
  Base64_Decoder objectRef;
  byte[] pbVar1;
  String pSVar2;
  boolean bVar3;
  StringBuilder objectRef_00;
  StringBuilder pSVar4;
  dword pdVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  
  objectRef_00 = new StringBuilder();
  pdVar5 = PasswordChecker_ENCODED_PARTS;
  iVar6 = pdVar5.length;
  iVar7 = 0;
  while( true ) {
    if (iVar6 <= iVar7) break;
    pSVar2 = pdVar5[iVar7];
    objectRef = Base64_getDecoder();
    pbVar1 = objectRef.decode(pSVar2);
    iVar8 = PasswordChecker_SALTS.length;
    while (iVar8 = iVar8 + -1, -1 < iVar8) {
      pbVar1 = PasswordChecker_xorWithSalt(pbVar1,PasswordChecker_SALTS[iVar8]);
    }
    pSVar4 = objectRef_00;
    pSVar2 = new String(pbVar1);
    objectRef_00.append(pSVar2);
    iVar7 = iVar7 + 1;
    objectRef_00 = pSVar4;
  }
  pSVar2 = objectRef_00.toString();
  bVar3 = pSVar2.equals(param1);
  return bVar3;
}



// Flags:
//   ACC_PRIVATE
//   ACC_STATIC
// 
// private static byte[] xorWithSalt(byte[], byte) 

byte[] xorWithSalt_byte___byte_byte__(byte[] param1,byte param2)

{
  byte[] pbVar1;
  int iVar2;
  
  pbVar1 = new byte[param1.length];
  iVar2 = 0;
  while( true ) {
    if (param1.length <= iVar2) break;
    pbVar1[iVar2] = param1[iVar2] ^ param2;
    iVar2 = iVar2 + 1;
  }
  return pbVar1;
}



// Flags:
//   ACC_STATIC
// 
// static (class initializer) 

void <clinit>_void(void)

{
  String[] ppSVar1;
  byte[] pbVar2;
  
  ppSVar1 = new String[9];
  ppSVar1[0] = "bGhyf2g=";
  ppSVar1[1] = "eg4IR3Y=";
  ppSVar1[2] = "CEoIYw0=";
  ppSVar1[3] = "CWN6SXI=";
  ppSVar1[4] = "YwgJYw0=";
  ppSVar1[5] = "SAljWQg=";
  ppSVar1[6] = "CUVjSAw=";
  ppSVar1[7] = "Y05ZSlk=";
  ppSVar1[8] = "TglZQQ==";
  PasswordChecker_ENCODED_PARTS = ppSVar1;
  pbVar2 = new byte[4];
  pbVar2[0] = 0x5a;
  pbVar2[1] = 0x3c;
  pbVar2[2] = 0x77;
  pbVar2[3] = 0x2d;
  PasswordChecker_SALTS = pbVar2;
  return;
}
```
I cleaned up the above code for java(ofcourse using AI):
```java
import java.util.Base64;
import java.util.Scanner;

public class PasswordChecker {
    private static final String[] ENCODED_PARTS = {
        "bGhyf2g=", "eg4IR3Y=", "CEoIYw0=", "CWN6SXI=", 
        "YwgJYw0=", "SAljWQg=", "CUVjSAw=", "Y05ZSlk=", "TglZQQ=="
    };
    private static final byte[] SALTS = {0x5a, 0x3c, 0x77, 0x2d};

    public PasswordChecker() {
        // Constructor
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the password: ");
        String inputPassword = scanner.nextLine();
        
        if (checkPassword(inputPassword)) {
            System.out.println("Access granted!");
        } else {
            System.out.println("Access denied!");
        }
        scanner.close();
    }

    private static boolean checkPassword(String inputPassword) {
        StringBuilder decodedString = new StringBuilder();
        
        for (String encodedPart : ENCODED_PARTS) {
            byte[] decodedBytes = Base64.getDecoder().decode(encodedPart);
            for (int i = SALTS.length - 1; i >= 0; i--) {
                decodedBytes = xorWithSalt(decodedBytes, SALTS[i]);
            }
            decodedString.append(new String(decodedBytes));
        }
        
        return decodedString.toString().equals(inputPassword);
    }

    private static byte[] xorWithSalt(byte[] data, byte salt) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ salt);
        }
        return result;
    }
}
```
The above code prompts the user to enter a password. It then decodes a series of Base64-encoded strings, applies a series of XOR operations using predefined salt values to the decoded byte arrays, and concatenates the results. The final decoded string is compared with the user input. If they match, access is granted; otherwise, access is denied.
We can use the folliwing java code:
```java
import java.util.Base64;

public class ReverseEngineerPassword {

    // Encoded parts of the password
    private static final String[] ENCODED_PARTS = {
        "bGhyf2g=", "eg4IR3Y=", "CEoIYw0=", "CWN6SXI=", "YwgJYw0=", 
        "SAljWQg=", "CUVjSAw=", "Y05ZSlk=", "TglZQQ=="
    };

    // Salts for XOR operation
    private static final byte[] SALTS = { 0x5a, 0x3c, 0x77, 0x2d };

    public static void main(String[] args) {
        // Step 1 & 2: Decode Base64 strings
        StringBuilder password = new StringBuilder();
        for (String part : ENCODED_PARTS) {
            byte[] decodedBytes = Base64.getDecoder().decode(part);
            // Step 3: Apply XOR with salts
            for (byte salt : SALTS) {
                decodedBytes = xorWithSalt(decodedBytes, salt);
            }
            // Step 4: Reconstruct the password
            password.append(new String(decodedBytes));
        }
        // Print the reconstructed password
        System.out.println("Reconstructed Password: " + password.toString());
    }

    private static byte[] xorWithSalt(byte[] data, byte salt) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ salt);
        }
        return result;
    }
}
```
This outputs us the flag as `PTNCTF24{J4v4_15_FuN_45_1t5_e45y_t0_rever5e}`.
You may ask why?
The above program reconstructs the password by:

1. **Decoding**: It decodes each Base64-encoded string in `ENCODED_PARTS`.
2. **XOR Operations**: Each decoded byte array is XORed sequentially with the bytes in the `SALTS` array to reverse the obfuscation.
3. **Concatenation**: The results of the XOR operations are concatenated into a single string.
4. **Output**: The concatenated string is printed, revealing the original password or flag.

The flag `PTNCTF24{J4v4_15_FuN_45_1t5_e45y_t0_rever5e}` is the original password obfuscated by the encoding and XOR process.

## Misc
### decrypt
It gave us a hash: `$y$j9T$dYMhyRh/23xp5tOaurjUg1$tiV5fTsrRm.rBAdtroibEydS9HDQ4/R/dbUMBDFfYl.`
Upon looking up on hash identifier website, it was found to be yescrypt which is not supported to be cracked by both hashcat and john, but... If we use `--format=crypt` with john, and the OS is Kali (which natively supports yescrypt) it cracks the hash for us. So, all I did was ran `john crackme.txt --format=crypt --wordlis=/usr/share/wordlist/rockyou.txt` and waited for it to crack the hash.
![](Pasted%20image%2020240802210043.png)
There we go, we got our password and the flag is `PTN{mathematics}`

### Discord
After doing million of lookup on the website (tenor.com) ofcourse, I couldnt find anything. I tried to look like bunch of stuffs like frames by frames too.
![](Pasted%20image%2020240802223746.png)
Then at the end I tried to "Copy Text" and pasted it in my terminal (tbh idk why lol) then found the flag there as `PTNCTF24{Let_the_game_begin}`.
![](Pasted%20image%2020240802224058.png)

### space-me
So the website was `http://unthinkable.me/ptn-ctf.html` where we were supposed to look for the flag. 
So, I was analyzing the source code and found nothing. Fired up burpsuite and noticed something unusual in response.
![](Pasted%20image%2020240803012751.png)
Since there were alot of spaces and tabs mixed. I saved the spaces/tabs in a `h1` file like this:
```
┌──(rezy㉿dev)-[~/Downloads/attachments]
└─$ echo "                                                                                                                                                
                                                                                                                                                        
                                                                                                                                                        
                                                                                                                                                            
                                                                                                                                                        
                                                                                                                                                           
                                                " > h1
```
Then I replaced all the spaces and tabs with 0 and 1 like:
```
┌──(rezy㉿dev)-[~/Downloads/attachments]
└─$ sed -e 's/\t/0/g' -e 's/ /1/g' h1 > output_file
                                                                                                                                                             
┌──(rezy㉿dev)-[~/Downloads/attachments]
└─$ cat output_file                       
10101111101010111011000110111100101010111011100110000100100100111100111010011001110011001010000011001110100011001010000010011110100100111001001110100000100111101001110111001111100010101000101110100000110011111010000011011001101000001100111010000010
```
I tried to check it's corresponding ASCII value, but nop! I again did the same thing but now tabs by 0 an spaces by 1.
```
┌──(rezy㉿dev)-[~/Downloads/attachments]
└─$ sed -e 's/\t/1/g' -e 's/ /0/g' h1 > final              
                                                                                                                                                             
┌──(rezy㉿dev)-[~/Downloads/attachments]
└─$ cat final      
01010000010101000100111001000011010101000100011001111011011011000011000101100110001100110101111100110001011100110101111101100001011011000110110001011111011000010110001000110000011101010111010001011111001100000101111100100110010111110011000101111101
```
Then when I check it's corresponding ASCII value, we get our flag as `PTNCTF{l1f3_1s_all_ab0ut_0_&_1}`.
![](Pasted%20image%2020240803013221.png)

### executionar
So here we got our ip and the port `misc.challenges.ctf.pentesternepal.com 4445`. I tried to connect to it using netcat which gives us a python code:
```python
def flag():
    with open('flag.txt', 'r') as f:
        print(f.read())


blacklist = [
    'import', 'os', 'sys', 'breakpoint',
    'flag', 'txt', 'read', 'eval', 'exec',
    'dir', 'print', 'subprocess', '[', ']',
    'echo', 'cat', '>', '<', '"', ''', 'open','flag','blacklist'
]


while True:
    command = input('Waiting for yours command: ')

    if any(b in command for b in blacklist):
        print('Invalid command!')
        continue

    try:
        exec(command)
    except Exception:
        print('You have been locked away...')
        exit(1337)
```
The Python script above defines a function called `flag` that reads and prints the contents of a file named "flag.txt." It also establishes a list of forbidden words called `blacklist`, which includes terms like 'import', 'os', 'sys', 'flag', and 'open'. The script then enters an infinite loop, prompting the user to input a command. If the input command contains any words from the blacklist, the script responds with "Invalid command!" and prompts the user again. If the command passes the blacklist check, the script attempts to execute it using the `exec` function. If any exception occurs during execution, the script prints "You have been locked away..." and exits with a specific error code. This setup is intended to prevent certain actions and protect sensitive information like the contents of "flag.txt."

The netcat session also asks me to input a command where I need to write a command to execute. To read flag, I am supposed to get into function `flag()`. Since we have blacklist in this script we can't do anything much. But....

In Python there is a global function called `globals` that returns a dictionary with all global functions and variables of the script.

```python
$ python3 -q
>>> globals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>}  
>>> a = 4444
>>> globals().get('a')
4444
```
They also works great with functions like:
```python
>>> def f():
...     print('hey')
...
>>> globals().get('f')
<function f at 0x101137920>  
>>> globals().get('f')()
hey
```
Now, we only need to use a string without single/double quotes. There are several ways, like using a list of integers as `bytes` or using `chr` and `+` like:
```python
>>> list(b'flag')
[102, 108, 97, 103]
>>> bytes([102, 108, 97, 103]).decode()
'flag'
>>> chr(102) + chr(108) + chr(97) + chr(103)
'flag'
```
Now, we have all the pieces. Let's join them and construct a payload: `globals().get(bytes((102, 108, 97, 103)).decode())()`. 
All I did was used this command and boom we get our flag.
```
┌──(rezy㉿dev)-[~]
└─$ nc misc.challenges.ctf.pentesternepal.com 4445

[// .. PYTHON SNIP .. \\]

Waiting for yours command: globals().get(bytes((102, 108, 97, 103)).decode())()
PTNCTF24{d1d_y0u_r34lly_Knew_That}
```




