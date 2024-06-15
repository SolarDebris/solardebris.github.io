---
title: DiceCTF 2023 and DiceCTF Quals 2024
category: WRITEUP, CTF, SECCOMP, RE, PWN
date: May 15th, 2024
description: Writeup of a few challenges from DiceCTF 2023.
---

## BOP


### Vulnerability

#### Getting the Leak

#### ORW Rop Chain



## Parallelism


### Static Analysis
When we take a look at the binary we can see that there is a string that is
64 characters long and contains the characters "d", "i", "c", "e", "{", "}". 
This can tell us that it is a flag scrambler.

### Patching the Binary
When we look at the binary, we can see that there is a function call that will
take in the scrambled input. We can patch this to print out the scrambled input
to determine the order of scrambling. If we patch it with puts it will print the
scrambled input. We can send a string of the alphabet and get the order

### Unscrambling the Flag
We can make a simple script that will reverse the scrambling on the encrypted flag
```
alp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-+"
test = "51sZIpMhSrd7HBUgRmCQPy23vu6joc-LEXT9KzbaOxefAtY8l+kJ0GNw4WnqFiDV"
enc_flag = "m_ERpmfrNkekU4_4asI_Tra1e_4l_c4_GCDlryidS3{Ptsu9i}13Es4V73M4_ans"
order = []

for a in alp:
    order.append(test.index(a))
flag = ""
for o in order:
    flag += enc_flag[o]

print(order)
print(flag)

```

Running the script gets us the flag
```
python solve_par.py
[39, 38, 29, 10, 42, 43, 15, 7, 61, 27, 50, 48, 17, 58, 28, 5, 59, 9, 2, 45, 25, 24, 55, 41, 21, 37, 44, 13, 18, 62, 32, 60, 53, 12, 4, 51, 36, 31, 6, 54, 40, 20, 19, 16, 8, 34, 14, 63, 57, 33, 46, 3, 52, 1, 22, 23, 56, 0, 26, 11, 47, 35, 30, 49]
dice{P4ral1isM_m4kEs_eV3ryt4InG_sUp3r_f4ST_aND_s3CuRE_a17m4k9l4}
```



## 
