---
title: HackTheBox Challenge - Flag Command
authors: Samarth
date: 2022-04-30 20:30:00 +0530
categories: [HackTheBox Challenge]
tags: [Web]
math: true
mermaid: true
---

![Banner](/assets/images/htb-chall/Flag%20Command/banner.png)

## Description

<b>Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape!</b>

## Solution

Since this is a web challenge, I began by browsing the target website provided.

![Target Website](/assets/images/htb-chall/Flag%20Command/1.png)

After selecting `start`, four choices appeared on the screen.

![4 Options](/assets/images/htb-chall/Flag%20Command/2.png)

Without any clear indication of the right path, I took a gamble and chose `HEAD NORTH`.

This led to another set of four options. Relying on trial and error, I managed to advance through three stages: `HEAD NORTH → FOLLOW A MYSTERIOUS PATH → SET UP CAMP`.

But when I reached the fourth stage, none of the available choices worked. No matter what I selected, the result was always the same - `Game Over`.

While checking the page source, I came across three .js files (`commands.js`, `game.js` and `main.js`).

In `main.js`, I observed that an API (`/api/monitor`) was being used to retrieve a `secret` upon selecting the correct options.

![main.js](/assets/images/htb-chall/Flag%20Command/3.png)

By analyzing the source code, I found the correct answers for the first three stages, but the fourth one remained unclear. So, I decided to check the Network tab in DevTools to see what resources were being requested. I found `/api/options` which was showing all the possible commands.

![Network Tab DevTools](/assets/images/htb-chall/Flag%20Command/4.png)

I found the value of `secret` so I have used the value of secret as a command and I found the flag.

![Flag](/assets/images/htb-chall/Flag%20Command/5.png)

Flag - 
```ruby
HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}
```

[![Pwned](/assets/images/htb-chall/Flag%20Command/pwned.png)](https://www.hackthebox.com/achievement/challenge/337503/646)

Thanks for reading this far. If you enjoyed the writeup, do support me [__here__](https://www.buymeacoffee.com/h4xplo1t){:target="_blank"}.



