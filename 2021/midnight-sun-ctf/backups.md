# Backups

## Problem

The backup of the home directories might contain too much information.

{% file src="../../.gitbook/assets/backup.tar.gz" %}

## Bob

Factordb attack worked.

`backup ~/Tools/RsaCtfTool/RsaCtfTool.py --publickey bob/.ssh/authorized_keys --private`

![](../../.gitbook/assets/57174126567043cda6f3da7cebc77c8b.png)

```bash
$ chmod 600 .ssh/id_rsa
$ ssh -p2222 -i .ssh/id_rsa bob@backup-01.play.midnightsunctf.se
midnight{Turn_electricity_t0_h347}
```

## Alice

Same thing for the first key, alice@work.

![](../../.gitbook/assets/e56e8184dd04437bb81459862d1cc742.png)

```bash
$ chmod 600 .ssh/id_rsa
$ ssh -p2222 -i .ssh/id_rsa alice@backup-01.play.midnightsunctf.se
midnight{factorization_for_the_Win}
Connection to backup-01.play.midnightsunctf.se closed.
```

