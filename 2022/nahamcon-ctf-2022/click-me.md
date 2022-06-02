# Click Me

This was a "clicker" mobile application. The goal was to get more than 99999999 clicks.

After decompiling the APK, we could see the following relevant part of the source code.

```java
public final void cookieViewClick(View view) {
    int i = this.CLICKS + 1;
    this.CLICKS = i;
    if (i >= 13371337) {
        this.CLICKS = 13371337;
    }
    ((TextView) findViewById(R.id.cookieCount)).setText(String.valueOf(this.CLICKS));
}

public final void getFlagButtonClick(View view) {
    Intrinsics.checkNotNullParameter(view, "view");
    if (this.CLICKS == 99999999) {
        Toast.makeText(getApplicationContext(), getFlag(), 0).show();
        return;
    }
    Toast.makeText(getApplicationContext(), "You do not have enough cookies to get the flag", 0).show();
}
```

We could find the instruction where the `CLICKS` is compared with 99999999, patch it, and recompile the APK. Looking at the Smali code, we see the following portion that corresponds to the check in `getFlagButtonClick`.

```smali
.line 34
iget p1, p0, Lcom/example/clickme/MainActivity;->CLICKS:I

const/4 v0, 0x0

const v1, 0x5f5e0ff

if-ne p1, v1, :cond_0

.line 35
invoke-virtual {p0}, Lcom/example/clickme/MainActivity;->getFlag()Ljava/lang/String;
```

In a nutshell, if the current number of clicks is not equal to 0x5f5e0ff (99999999), the code jumps over the `getFlag()` call to the `cond_0` label somewhere below.

All we have to do is to change this instruction to

```smali
if-gt p1, v1, :cond_0
```

and [recompile the APK](https://gist.github.com/PuKoren/d0ec0c98350c0e92f467). Now the check is bypassed!

![](<../../.gitbook/assets/image (84) (2).png>)
