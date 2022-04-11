# Payback

## Description

> We got ourself a premium flag shop.

{% file src="../../.gitbook/assets/payback.zip" %}

## Solution

### Code Review

The app consists of two parts - the frontend and the payment backend (`front` and `payment`). Interestingly the user accounts for the frontend and backend are separate!

When performing a transaction, a message is signed using ED25519 to prevent tampering. The message format is `user{u}amount{amount}nonce{nonce}`. The amount is checked, and since our balance is 0, we can only use 0 for the amount.

```python
@app.route('/pay', methods=['GET', 'POST'])
def pay():
    if 'logged_in' not in session:
        return redirect(url_for('login', next=request.url))

    if request.method == "GET":
        return render_template('amount.html')

    amount = int(request.form.get('amount', 0))

    user = User.query.filter_by(name=session['name']).first()

    if amount > user.balance:
        return "Insufficient balance", 400

    if amount < 0:
        return "Invalid amount", 400

    cb = request.args['callback']
    u = request.args['user']
    nonce = request.args['nonce']

    m = f"user{u}amount{amount}nonce{nonce}".encode()

    sig = SIG_KEY.sign(m, encoding='hex')

    user.balance -= amount
    db.session.commit()

    return redirect(f"{cb}/callback?user={u}&amount={amount}&nonce={nonce}&sig={sig.decode()}", code=302)
```

The user is redirected to `/callback` on the frontend application.

This message is then verified by the frontend.

```python
def callback():
    message, signature = b"", b""

    for param in request.args:
        if param == "sig":
            signature = request.args[param].encode()
            continue

        for value in request.args.getlist(param):
            message += param.encode()
            message += value.encode()
    
    print("Message", message, flush=True)

    try:
        verify_key.verify(signature, message, encoding='hex')

        user = User.query.filter_by(name=session['name']).first()
        nonce = int(request.args['nonce'])

        if nonce <= user.nonce:
            raise Exception

        user.nonce = nonce
        user.balance += int(request.args.get('amount', 0))
        db.session.commit()
    except:
        traceback.print_exc()
        return "Something went wrong", 400

    return redirect('home')
```

Notice that it iterates through the list of GET query parameters and adds them to the message before verifying that the message is the same as the one generated above.

Then, `request.args.get('amount')` is added to the user balance.

### Parameter Pollution

Well, what if there are two `amount` arguments? Only the first occurrence is returned by `request.args.get` (so the amount added to the user's balance is the first `amount` argument), yet both occurrences are added to the message to be verified.

Since the message format is `user{u}amount{amount}nonce{nonce}` we can simply create a user with the username `FRONTEND_USERNAMEamount1337`. The resulting message is then `userFRONTEND_USERNAMEamount1337amount0nonceNONCE`.

The server gives us the signature for this message.

Then, we perform parameter pollution on the frontend:

`GET /callback?user=FRONTEND_USERNAME&amount=1337&amount=0&nonce=NONCE&sig=SIGNATURE`.

Due to the way the frontend processes the parameters, this will result in the exact same message as above being checked, although carrying a different meaning.

![](<../../.gitbook/assets/image (83) (1) (1) (1).png>)

We have successfully added 1337 coins to our account!

The flag is `CSR{sometimes_it's_really_hard_to_create_good_flags}`
