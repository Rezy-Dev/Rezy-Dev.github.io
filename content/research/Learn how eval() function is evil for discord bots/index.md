---
title: Pentester Nepal's 2024 CTF Writeups
date: 2024-12-07
description: Learn how eval() function is evil for discord bots
summary: Learn how eval() function is evil for discord bots
draft: false
tags:
  - Eval
  - Python
  - Discord
  - Bot
---
Hello, everyone! In this blog, I want to showcase a dangerous function that, if used improperly, can cause serious harm, whether in a web app or elsewhere. In this article, I’ll focus on the abuse of `eval()` in Discord bots. While it's rare to find it, if you ever come across it or discover that a bot is using it, it's incredibly dangerous.

# Introduction
For this demonstration, I’ll be using the Discord bot source code I wrote for the WSC CTF 2024 Qualifier. The bot was titled "Evil-Bot". I won’t go into too much detail, but here’s the screenshot I shared with them:
![](assets/Pasted%20image%2020241207132908.png)

The screenshot already provided most of the hints needed to solve the CTF. However, we won’t be using the image or inviting the bot using the client ID from the screenshot, as the bot is now down. Instead, I encourage you to set up the bot locally using Docker and abuse it in that environment.

# Download and Setup
Since I don't want to go over how to download the bot’s source code and set it up in your local environment, I’ve written a detailed `README.md` on how to get the source code and bring the Discord bot online. You can find it in the GitHub repository here: https://github.com/Rezy-Dev/Evil-Bot

You will need to install Docker Engine, which you can do by following the instructions here: https://docs.docker.com/engine/install/ubuntu/ (this link is for Ubuntu, but you can find installation instructions for other distributions in the documentation). If you're using Windows or macOS, you can also find installation guides on the same website.

# About The Bot
Before starting the exploitation and looking at source code, we will generally learn how the asset works. In this case, we will learn how the discord bot works and what feature it gives us.

Below is an image of the `!help` command, which lists all the other commands that can be used.
![](assets/Pasted%20image%2020241207134000.png)

Without wasting much time looking at each commands, let me give you general overview of what the following command does using following table:
![](assets/Pasted%20image%2020241207134330.png)

# Accessing vulnerable function
So we will use `!work` for few times until we have enough cash to purchase calculator. The calculator costs $500 if you check the source code:
```python
@bot.command()
async def buy(ctx, item):
    data = load_data()
    user_id = str(ctx.author.id)
    if item.lower() == "calculator":
        cost = 500 ## THIS IS THE COST OF CALCULATOR
        if user_id not in data["users"] or data["users"][user_id]["cash"] < cost:
            await ctx.send("You don't have enough cash to buy the calculator.")
            return
        data["users"][user_id]["cash"] -= cost
        data["users"][user_id]["calculator"] = True
        save_data(data)
        await ctx.send("You have purchased the calculator!")
```

When I purchase `!buy calculator` we get access to `!calculator` command.
![](assets/Pasted%20image%2020241207134752.png)

And we can use following command to calculate:
![](assets/Pasted%20image%2020241207134840.png)

This seems interesting, doesn’t it? The bot directly accepts the input `!calculator <math expression>`, calculates it, and shows us the result.

# eval() is actually evil
How is it directly accepting both the operator and operand from the user and calculating the result? It’s all thanks to the `eval()` function.

The `eval()` function in Python takes a string and evaluates it as a Python expression. It can execute any valid Python code within the string passed to it. For example:
```python
expression = "3 + 5 * 2"
result = eval(expression)
print(result)  # Output: 13
```

In this example, `eval()` takes the string `"3 + 5 * 2"`, evaluates it as a Python expression, and returns the result `13`. 

It can execute arbitrary Python code, return a result, or perform operations based on the expression passed. In essence, it works like the interactive console in Python, where you can enter Python code, and the interpreter executes it immediately.

## How Does `eval()` Work?
`eval()` operates by parsing the string expression and evaluating it as Python code. Here’s the basic process:

1. **String to Code**: The string passed to `eval()` is parsed into Python bytecode.
2. **Execution**: The bytecode is executed in the current environment (i.e., it can access variables, functions, and objects defined in the current scope).
3. **Return Value**: The result of the expression is returned.

It works in a very similar way to the Python interactive shell. In the interactive shell, you type in a Python expression, and the interpreter immediately evaluates and returns the result:
```python
╭─rezy@dev ~  
╰─➤  python3                    
Python 3.12.3 (main, Sep 11 2024, 14:17:37) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 3 + 5 * 2
13
```

This is almost identical to how `eval()` functions. It evaluates an expression and gives you an immediate result.

## The Risks of `eval()`
While `eval()` is incredibly flexible and powerful, it comes with **severe security risks**. The most dangerous aspect of `eval()` is that it can execute arbitrary code. This makes it a prime target for exploitation if user input is not properly sanitized.

### Let's exploit `eval()`
Since we have the Discord bot, which uses the `eval()` function for the `!calculator` command, we can exploit it for remote code execution.

Since we know the Discord bot uses the `!calculator 1+1` command, which is evaluated using the `eval()` function, we can abuse this by importing the `os` module and calling a function of our choice to execute system commands on the host system. For example, we can execute the following command:
```python
!calculator __import__('os').popen('whoami').read()
```

This exploits the `eval()` function to import the `os` module, use `popen()` to execute the `whoami` system command, and then return the result, which will reveal the username of the current system user (i.e, `bot_user` if you check `Dockerfile`).
![](assets/Pasted%20image%2020241207140355.png)

If we check the source code of the bot, we can see the vulnerable code that directly passes the user's input to the `eval()` function:
```python
@bot.command()
async def calculator(ctx, *, expression):
    data = load_data()
    user_id = str(ctx.author.id)
    if user_id not in data["users"] or not data["users"][user_id].get(
        "calculator", False
    ):
        await ctx.send("You don't own calculator bro.")
        return
    try:
        result = eval(expression)
        await ctx.send(f"The result of `{expression}` is `{result}`.")
    except Exception as e:
        await ctx.send(f"Error in calculation! :warning:")
```

We can even read files on the system like this:
![](assets/Pasted%20image%2020241207140642.png)

# Containerization made it somewhat safer
Since we were running the bot in a Docker container, the remote code execution (RCE) was limited to the container and not the main system. However, if the container itself is vulnerable, it could be escaped, leading to a serious security issue. Therefore, it’s crucial to practice both safe coding and secure deployment.

## Safe Deployment
For safe deployment of a Discord bot (or any other app) in a Docker container, it's essential to implement strict security controls to minimize potential risks. First, disable root access within the container by ensuring the bot runs as a non-privileged user, which reduces the impact of any exploitation. 

Limit the commands and system calls that can be executed inside the container by using Docker’s security features, such as setting restrictive `capabilities` and mounting only necessary volumes. 

Additionally, make sure the container’s network access is tightly controlled, preventing any unnecessary exposure to the host or external services. Regularly update the container images to ensure they include the latest security patches, and consider using Docker's built-in features like read-only file systems or limiting container resources to further minimize attack surfaces.

# Secure Coding
Do you think safe deployment alone is enough? The answer is a big NO! An attacker can still penetrate and enumerate how the deployment is configured and how the code is written, which makes the asset vulnerable. Therefore, it's crucial to limit how users provide input to further reduce potential risks.

Input validation and sanitization are essential to ensure that only expected and safe inputs are processed by your code. In the case of our Discord bot, using the `eval()` function to directly evaluate user-provided input can lead to severe security issues, such as remote code execution (RCE). Even though safe deployment practices can isolate the environment, an attacker can still exploit vulnerabilities in the code. It is crucial to validate and limit the scope of what users can submit, especially when dealing with potentially dangerous functions like `eval()`.

### Fixing the Code to Make It Safer
Instead of directly passing user input to `eval()`, we should **sanitize** and **validate** the input to ensure that it only contains safe mathematical expressions. One way to achieve this is by using libraries like `ast.literal_eval()` or writing a custom parser for mathematical expressions. 

Here's a safer alternative with input validation:
```python
import discord
from discord.ext import commands
import random
import json
import os
import re # Importing Regular Expression used for Validation

[..SNIP..]

@bot.command()
async def calculator(ctx, *, expression):
    data = load_data()
    user_id = str(ctx.author.id)
    if user_id not in data["users"] or not data["users"][user_id].get("calculator", False):
        await ctx.send("You don't own calculator bro.")
        return

    # Validate the input to allow only numbers, operators, and parentheses
    if not re.match(r'^[0-9+\-*/().\s]*$', expression):
        await ctx.send("Invalid input! Only numbers and basic arithmetic operators are allowed.")
        return

    try:
        result = eval(expression)  # Safe now since input is validated
        await ctx.send(f"The result of `{expression}` is `{result}`.")
    except Exception as e:
        await ctx.send(f"Error in calculation! :warning:")

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
bot.run(DISCORD_TOKEN)
```


### Best Practices for Using `eval()`
Using `eval()` in code can be risky, but if it’s absolutely necessary, there are several steps you can take to minimize the risks. First, you should **limit the scope** in which `eval()` operates by using the `globals` and `locals` parameters. This helps control the environment and prevents access to dangerous functions. For example, you can restrict built-in functions like `os.system()` from being accessed by passing `{"__builtins__": None}`.
```python
result = eval(expression, {"__builtins__": None}, {})
```

Another key practice is **validating** and **sanitizing** user input to ensure that only safe characters and expressions are passed to `eval()`. This helps avoid malicious code execution. If possible, it’s better to avoid using `eval()` altogether and consider safer alternatives. For example, you could use libraries like `ast.literal_eval()` for parsing simple data types or `simpleeval` for evaluating mathematical expressions, which are far less risky than `eval()`.

Additionally, **error handling** is crucial when using `eval()`. Wrapping the evaluation in a try-except block helps prevent unexpected crashes, handles errors gracefully, and ensures that the error message is not revealed verbosely to the user.

# Conclusion
In this blog, we explored the vulnerabilities of the "Evil-Bot," a Discord bot, specifically focusing on the security risks posed by the use of the `eval()` function. By containerizing the bot using Docker, we mitigated the impact of any potential Remote Code Execution (RCE) attacks, as the bot's code was isolated within a secure environment. However, containerization alone is not enough to ensure complete security. It's crucial to adopt secure coding practices, such as validating user input and avoiding dangerous functions like `eval()`, to prevent malicious exploitation.

In production environments, isolating applications through containerization is a best practice, but securing the code itself remains paramount. I encourage all developers to adopt safer coding techniques, implement strict input validation, and leverage isolation methods like Docker to protect against vulnerabilities in production bots. By doing so, we can significantly reduce the risks of RCE and create more secure, reliable applications.