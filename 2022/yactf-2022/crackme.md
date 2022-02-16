# Crackme

This was a simple reversing challenge. Looking at the validation function, we could see that the key is relatively simple to bruteforce.

```c
_BOOL8 __fastcall check(const char *a1)
{
  int i; // [rsp+14h] [rbp-6Ch]
  int k; // [rsp+14h] [rbp-6Ch]
  int m; // [rsp+14h] [rbp-6Ch]
  int n; // [rsp+14h] [rbp-6Ch]
  int j; // [rsp+18h] [rbp-68h]
  int v7; // [rsp+1Ch] [rbp-64h]
  int v8; // [rsp+24h] [rbp-5Ch]
  int v9; // [rsp+30h] [rbp-50h]
  int v10; // [rsp+34h] [rbp-4Ch]
  int v11; // [rsp+38h] [rbp-48h]
  int v12; // [rsp+3Ch] [rbp-44h]
  int v13; // [rsp+40h] [rbp-40h]
  int v14; // [rsp+44h] [rbp-3Ch]
  int v15; // [rsp+48h] [rbp-38h]
  int v16; // [rsp+4Ch] [rbp-34h]
  int v17; // [rsp+50h] [rbp-30h]
  int v18; // [rsp+54h] [rbp-2Ch]
  int v19; // [rsp+58h] [rbp-28h]
  int v20; // [rsp+5Ch] [rbp-24h]
  int v21; // [rsp+60h] [rbp-20h]
  int v22; // [rsp+64h] [rbp-1Ch]
  int v23; // [rsp+68h] [rbp-18h]
  int v24; // [rsp+6Ch] [rbp-14h]
  unsigned __int64 v25; // [rsp+78h] [rbp-8h]

  v25 = __readfsqword(0x28u);
  if ( strlen(a1) != 19 )
    return 0LL;
  for ( i = 4; i <= 19; i += 5 )
  {
    if ( i <= 14 && a1[i] != 45 )
      return 0LL;
    for ( j = i - 4; j < i; ++j )
    {
      if ( a1[j] <= 47 || a1[j] > 57 )
        return 0LL;
    }
  }
  v9 = toi((unsigned int)*a1);
  v10 = toi((unsigned int)a1[1]);
  v11 = toi((unsigned int)a1[2]);
  v12 = toi((unsigned int)a1[3]);
  v13 = toi((unsigned int)a1[5]);
  v14 = toi((unsigned int)a1[6]);
  v15 = toi((unsigned int)a1[7]);
  v16 = toi((unsigned int)a1[8]);
  v17 = toi((unsigned int)a1[10]);
  v18 = toi((unsigned int)a1[11]);
  v19 = toi((unsigned int)a1[12]);
  v20 = toi((unsigned int)a1[13]);
  v21 = toi((unsigned int)a1[15]);
  v22 = toi((unsigned int)a1[16]);
  v23 = toi((unsigned int)a1[17]);
  v24 = toi((unsigned int)a1[18]);
  if ( v9 != 8 )
    return 0LL;
  if ( v14 != 5 )
    return 0LL;
  if ( v16 != 6 )
    return 0LL;
  if ( v17 != 7 )
    return 0LL;
  if ( v18 != 8 )
    return 0LL;
  if ( v19 != 2 )
    return 0LL;
  if ( v21 != 3 )
    return 0LL;
  if ( v22 != 4 )
    return 0LL;
  if ( v23 != 7 )
    return 0LL;
  for ( k = 0; k <= 3; ++k )
  {
    if ( *(&v13 + k) <= 0 || *(&v13 + k) > 7 )
      return 0LL;
  }
  for ( m = 0; m <= 3; ++m )
  {
    if ( *(&v17 + m) <= 1 || *(&v17 + m) > 9 )
      return 0LL;
  }
  for ( n = 0; n <= 3; ++n )
  {
    if ( *(&v21 + n) <= 2 || *(&v21 + n) > 8 )
      return 0LL;
  }
  v7 = v11 + v10 + 8 + v12;
  v8 = v19 + v18 + v17 + v20;
  if ( v23 + v22 + v21 + v24 != (v15 + v14 + v13 + v16 + v7 + v8) / 3 )
    return 0LL;
  if ( v7 != (v23 + v22 + v21 + v24) / 2 )
    return 0LL;
  if ( v15 + v14 + v13 + v16 != v8 - 7 )
    return 0LL;
  if ( v8 + v7 == 33 )
    return v13 + v8 == 31;
  return 0LL;
}
```

Knowing that there are only 7 unknown digits, we could bruteforce the key by checking whether it fulfills the requirements.

```python
start = 'yactf{'

remaining = [0 for _ in range(19)]
for i in range(4, 20, 5):
    if i <= 14:
        remaining[i] = chr(45)

remaining[0] = 8
remaining[6] = 5
remaining[8] = 6
remaining[10] = 7
remaining[11] = 8
remaining[12] = 2
remaining[15] = 3
remaining[16] = 4
remaining[17] = 7

print(remaining)

maximum = 10000000
curr = 0
while curr != maximum:

    # 7 unknowns
    num_string = str(curr).zfill(7)
    test_remaining = remaining.copy()
    
    j = 0
    for i in range(len(test_remaining)):
        if test_remaining[i] == 0:
            test_remaining[i] = int(num_string[j])
            j += 1

    print(test_remaining)

    v7 = test_remaining[2] + test_remaining[1] + 8 + test_remaining[3]
    v8 = 2 + 8 + 7 + test_remaining[13]

    try:
        assert 7 + 4 + 3 + test_remaining[18] == (test_remaining[7] + 5 + test_remaining[5] + 6 + v7 + v8) // 3
        assert v7 == (7 + 4 + 3 + test_remaining[18]) // 2
        assert test_remaining[7] + 5 + test_remaining[5] + 6 == v8 - 7
        assert v8 + v7 == 33
        assert test_remaining[5] + v8 == 31

    except:
        curr += 1

    else:
        print(''.join(map(str, test_remaining)))
        break
```

The key is `yactf{8000-6516-7828-3473}`
