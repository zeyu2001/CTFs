---
description: Python is weird.
---

# The Blacksmith

## Introduction

This was one of the more interesting Web challenges from this CTF, because it taught me something new about Python and how it handles augmented assignment statements.

The challenge centered around a "market" API, where customers could buy "regular" and "exclusive" items.

```python
SHOP = {
    "customers": [],
    "inventory": {
        "regular": (
            Weapon("brokensword", 5, 0),
            Weapon("woodensword", 5, 1),
            Weapon("stonesword", 10, 2),
            Weapon("ironsword", 50, 10),
            Weapon("goldsword", 100, 20),
            Weapon("diamondsword", 500, 100),
        ),
        "exclusive": (Weapon("flagsword", 5, 0),),
    },
}
```

The customer's eligibility to purchase exclusive items depends on the customer's `tier`, which checks if the customer's `fame` and the sum of their loyalty `point_history` exceeds 1337.

```python
@dataclass
class Customer:
    id: str
    gold: int
    loyalty: Loyalty | RestrictedLoyalty

    @property
    def tier(self):
        if (self.loyalty.fame + sum(self.loyalty.point_history)) > 1337:
            return "exclusive"
        return "regular"

    @staticmethod
    def index_from_id(id):
        for idx, customer in enumerate(SHOP["customers"]):
            if customer.id == id:
                return idx
        return None
```

## Exploring the API

The first bug that might have been immediately obvious when visiting the page is that the index page is unauthenticated. Although the `customer_id` parameter is checked, a `HTTPException` is called but _not raised_.

```python
@app.get("/")
def index(customer_id=""):
    customer = Customer.index_from_id(customer_id)

    if customer is None:
        HTTPException(status_code=401)

    shop_items = [
        *SHOP["inventory"]["exclusive"],
        *SHOP["inventory"]["regular"],
    ]
    if LOYALTY_SYSTEM_ACTIVE:
        return shop_items

    return [item for item in shop_items if item.loyalty_points == 0]
```

This pattern does not repeat itself in any of the other API routes, though. We can see that we in fact need a valid `customer_id` to access the rest of the features.

```python
if customer_idx is None:
    raise HTTPException(status_code=401)
```

Let's register a new user. Because `LOYALTY_SYSTEM_ACTIVE` is set to `False`, we are given a `RestrictedLoyalty`  which is a `namedtuple`. This is an [immutable](https://realpython.com/courses/immutability-python/) data structure. We also start with 5 `gold`.

```python
LOYALTY_SYSTEM_ACTIVE = False

...

RestrictedLoyalty = namedtuple("RestrictedLoyalty", ["fame", "point_history"])

...

@app.get("/customer/new")
def register():
    if LOYALTY_SYSTEM_ACTIVE:
        customer = Customer(id=uuid4().hex, gold=5, loyalty=Loyalty(1, []))
    else:
        # Ensure loyalty immutable
        customer = Customer(
            id=uuid4().hex, gold=5, loyalty=RestrictedLoyalty(1, [])
        )

    SHOP["customers"].append(customer)
    print(SHOP['customers'])

    return {"id": customer.id}
```

Visiting this endpoint provides us with a new customer ID.

```http
HTTP/1.1 200 OK
date: Wed, 07 Dec 2022 08:28:52 GMT
server: uvicorn
content-length: 41
content-type: application/json
Connection: close

{"id":"710eab1db93e413192e908358c38c168"}
```

A `/battle` endpoint provides a potential way to increase our `fame`, but as we saw earlier, `LOYALTY_SYSTEM_ACTIVE` is `False` so this is not possible.

```python
@app.get("/battle")
def battle(customer_id=""):
    customer_idx = Customer.index_from_id(customer_id)
    if customer_idx is None:
        raise HTTPException(status_code=401)

    is_victorious = choice([True, False])

    if is_victorious and LOYALTY_SYSTEM_ACTIVE:
        SHOP["customers"][customer_idx].loyalty.fame += 1

    message = "You won!" if is_victorious else "You lost!"

    return {"result": message}
```

Since our goal is to purchase the `flagsword`, we should take a look at the `/buy` endpoint. Since this function is rather long, I'll break it up into parts.

First, we have to provide our `customer_id` and a list of `items` that we want to buy.

```python
def weapon_from_name(weapons, name):
    for weapon in weapons:
        if weapon.name == name:
            return weapon
    return None
    
...

@app.get("/buy")
def buy_item(customer_id="", items: list[str] | None = Query(default=[])):
    customer_idx = Customer.index_from_id(customer_id)

    if customer_idx is None:
        raise HTTPException(status_code=401)

    if items is None:
        return {"purchased": ""}
```

The weapons that we are eligible to purchase depends on our customer `tier`. Since we are a `regular` plebeian, we can only get to purchase regular weapons. Among the regular weapons, we only have enough gold to buy either a `brokensword` or a `woodensword`.

```python
    match SHOP["customers"][customer_idx].tier:
        case "regular":
            get_weapon = partial(
                weapon_from_name, SHOP["inventory"]["regular"]
            )
        case "exclusive":
            get_weapon = partial(
                weapon_from_name,
                [
                    *SHOP["inventory"]["regular"],
                    *SHOP["inventory"]["exclusive"],
                ],
            )
        case _:
            raise HTTPException(status_code=500)
            
    cart = []
    for item in items:
        weapon = get_weapon(item)
        if weapon is None:
            raise HTTPException(status_code=404)
        cart.append(weapon)
```

If any of the items we are attempting to buy exceeds our available `gold`, a 403 Forbidden is returned. The total price of all items is summed up and the loyalty points of the items are stored in a `point_history` list.

```python
    total_price = 0
    point_history = []
    for item in cart:
        if item.price > SHOP["customers"][customer_idx].gold:
            raise HTTPException(status_code=403)
        total_price += item.price
        if item.loyalty_points > 0:
            point_history += [item.loyalty_points]
```

If there are any loyalty points involved, the code attempts to add the `point_history` list to our customer `point_history` record, [EAFP](https://realpython.com/python-lbyl-vs-eafp/#the-easier-to-ask-forgiveness-than-permission-eafp-style)-style.

```python
    try:
        if len(point_history) > 0:
            SHOP["customers"][
                customer_idx
            ].loyalty.point_history += point_history
        if SHOP["customers"][customer_idx].gold < total_price:
            raise HTTPException(status_code=403)
        SHOP["customers"][customer_idx].gold -= total_price
    except Exception as e:
        raise HTTPException(status_code=403)
```

Note that because our loyalty object is an immutable `namedtuple`, this will definitely raise an exception. In fact, attempting to set any attribute in the `namedtuple` will cause an `AttributeError` when performing the assignment.

```python
>>> from collections import namedtuple
>>> RestrictedLoyalty = namedtuple("RestrictedLoyalty", ["fame", "point_history"])
>>> my_loyalty = RestrictedLoyalty(0, [])
>>> my_loyalty.fame = 1
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
AttributeError: can't set attribute
```

Finally, if we managed to purchase a `flagsword`, then we are presented with the flag.

```python
    if "flagsword" in [weapon.name for weapon in cart]:
        return {"purchased": FLAG}

    return {"purchased": cart}
```

## Immutability is Misleading

I didn't manage to spot this bug for quite a while, but luckily this challenge is one that can be solved by fuzzing and logging out as many things as possible.

If we just analyze the behaviour of the application when attempting to set the `point_history`, we would quickly find that something weird is going on.

```python
try:
    if len(point_history) > 0:
        SHOP["customers"][
            customer_idx
        ].loyalty.point_history += point_history
    if SHOP["customers"][customer_idx].gold < total_price:
        raise HTTPException(status_code=403)
    SHOP["customers"][customer_idx].gold -= total_price
except Exception as e:
    print("Exception: ", e)
    print("Point history: ", SHOP["customers"][customer_idx].loyalty.point_history)
    raise HTTPException(status_code=403)
```

By sending a request to buy a `woodensword` (costing 5 gold and having 1 loyalty point) as follows

```
/buy?customer_id=96d04a31cdca47dba99e588f85d28b1b&items=woodensword
```

We see that the `AttributeError` is raised as expected, but somehow, our point history has actually been modified!

```
Exception:  can't set attribute
Point history:  [1]
INFO:     172.17.0.1:59960 - "GET /buy?customer_id=96d04a31cdca47dba99e588f85d28b1b&items=woodensword HTTP/1.1" 403 Forbidden
```

Wait... what??? I thought the `namedtuple` is immutable?

## Digging Deeper

I wanted to dig a little deeper to investigate the root cause of this weird behaviour that challenged my _Introduction to Programming_ Python knowledge.

Immutability in Python is tricky - while the tuple itself is immutable, if a tuple contains a mutable object, that object can still be modified [in-place](https://en.wikipedia.org/wiki/In-place\_algorithm). For example, if we have a `list` within a `tuple`, that list can still be modified in-place using a method such as `append`.

```python
>>> tup = (["hello"], )
>>> tup[0].append("world")
>>> tup
(['hello', 'world'],)
```

But wasn't the code performing _assignment_ instead of an in-place operation? Didn't the exception get raised anyway?

Turns out, all the _Introduction to Programming_ lessons that taught me `x += y` was the same as `x = x + y` were wrong. Taking a look at Python's [documentation](https://docs.python.org/3/reference/simple\_stmts.html) on statements, we would see that it is explained that these two statements are not quite the same.

> An augmented assignment expression like `x += 1` can be rewritten as `x = x + 1` to achieve a similar, but not exactly equal effect. In the augmented version, `x` is only evaluated once. Also, when possible, the actual operation is performed _in-place_, meaning that rather than creating a new object and assigning that to the target, the old object is modified instead.

Hmm... ok, but if the operation is only performed in-place, why raise the error?

I then looked up Python's [in-place operators](https://docs.python.org/3/library/operator.html), and found that the `+=` operator is just syntactic sugar for the `__iadd__` method. Basically, when doing `x += y`, we are really doing:

```python
x = x.__iadd__(y)
```

and because some objects like tuples are immutable, it is not _guaranteed_ that the operation would be in-place, so there is still an assignment step regardless of whether the operation was in-place or not.

For list objects, the `__iadd__` method (implemented as [`list_inplace_concat`](https://github.com/python/cpython/blob/main/Objects/listobject.c#L985) in the CPython source) is just a wrapper for `list_extend`, an in-place method. We see that the original list object is still returned to make the assignment step work.

```c
static PyObject *
list_inplace_concat(PyListObject *self, PyObject *other)
{
    PyObject *result;

    result = list_extend(self, other);
    if (result == NULL)
        return result;
    Py_DECREF(result);
    return Py_NewRef(self);
}
```

It is at the _assignment_ step that an error is raised, because the immutable `namedtuple` does not support item assignments. But by the time this happens, the list has already been modified.

## Back to the Challenge

In order to solve this challenge, we just have to buy the `woodensword` 1337 times. Note that because our gold amount is checked against `total_price` only _after_ the `point_history` assignment is attempted, we can just add the `woodensword` to our cart 1337 times.

```python
if len(point_history) > 0:
    SHOP["customers"][
        customer_idx
    ].loyalty.point_history += point_history
if SHOP["customers"][customer_idx].gold < total_price:
    raise HTTPException(status_code=403)
SHOP["customers"][customer_idx].gold -= total_price
```

First, we send a request to increase our loyalty point history 1337 times.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-07 at 5.35.10 PM.png" alt=""><figcaption></figcaption></figure>

Then we could unlock and buy the `flagsword`!

```
/buy?customer_id=96d04a31cdca47dba99e588f85d28b1b&items=flagsword
```

```http
HTTP/1.1 200 OK
date: Wed, 07 Dec 2022 09:35:01 GMT
server: uvicorn
content-length: 83
content-type: application/json
Connection: close

{"purchased":"STF22{this_is_a_dummy_flag_for_your_personal_testing_do_not_submit}"}
```
