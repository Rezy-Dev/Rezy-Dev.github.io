---
title: "TUCTF 24 - Silly Cloud"
date: 2025-01-27
description: The "Silly Cloud" challenge in TUCTF 24 involved exploiting Kubernetes security through LFI to access an internet-facing API.
summary: The "Silly Cloud" challenge in TUCTF 24 involved exploiting Kubernetes security through LFI to access an internet-facing API.
draft: false
Tags:
- CTF
- Kubernetes Security
- TUCTF
- 2025
---

Hello everyone! Welcome to the writeup for a challenge called _'Silly Cloud'_ from TUCTF 24. I found this challenge both fun and challenging! It revolved around interacting with the internet-facing REST API of Kubernetes (K8s).

![](assets/Pasted%20image%2020250127192722.png)

# Looking around the web
The interface of this website is shown in the screenshot below. It was essentially a cloud control manager, and I started poking around the website to look for anything interesting (if I could find something, lol).
![](assets/Pasted%20image%2020250127192744.png)

Interestingly, the dashboard for each function had a 'Deploy' button, but all of them threw errors. **BUTTT BUTTTT SIRRRR**, something simple yet sneaky caught my attention! 😂 I discovered a sweet and straightforward LFI (Local File Inclusion) in the 'View Logs' button, which redirected to the `/logs?service=registry` endpoint. Using this, I could easily traverse the filesystem and read local files like `/etc/passwd`, `/etc/hosts`, and more—well, as long as the web service had permission. 😏

## Troll begin here
Since I found the LFI, my first move was to try reading the flag from common directories where it might be stored, like `../../../flag.txt` and other parts of the filesystem. But nope—no luck. I mean, it _shouldn’t_ be that easy, especially since this challenge was marked as 'Medium,' haha.

So, my next plan was to read the source code of the app to figure out what was going on. But first, I had to figure out what kind of app this even was!

I randomly visited a non-existent endpoint, `/ddd`, and the server responded with a 'Not Found' page. This type of response felt pretty familiar—it’s common for Python Flask applications. Since I have decent experience working with Flask, I suspected the app might be built using it.

So, my next move was to read the source code of files ending with `.py` to dig deeper into the application.
![](assets/Pasted%20image%2020250127193628.png)

I tried accessing random non-existent directories in the filesystem, and this revealed the default directory the application was looking at: `logs/*`.
![](assets/Pasted%20image%2020250127194000.png)

For some reason, my brain pointed me toward the idea that the source code should be in a directory one level back. It’s probably named either `main.py` or `app.py`, as that’s common practice for naming the main file in most Flask web applications.

I managed to retrieve the source code of the app by exploiting the LFI and accessing `/logs?service=../app.py`. Bingo! This gave me the full source code of the application.

BUT BUT BUT... is it actually _bingo_ yet?! LMAO!!! Let’s find out!

Instead of throwing the entire source code at you, let me just highlight the interesting route here:
```python
@app.route('/api/secrets')
def get_flag():
    return subprocess.check_output(['cat', 'flag.txt'])
```

I’m sure you can guess what this does.

```bash
╭─rezy@dev ~  
╰─➤  curl https://silly-cloud.tuctf.com/api/secrets               
Tr0lL{this_is_a_fake_flag}

Look deeper! There is a hidden flag somewhere in the cloud!
```

You probably guessed it—it's a troll, haha! 😆 So, this route actually tells us a lot about the challenge. It’s not just about getting the flag directly; we need to dig deeper to find the real flag. And yep, it's somewhere in the 'CLOUD'.

## Enumerating More into File System
At the time of writing this writeup, I already know the actual path to look at, but when I was attempting the challenge, it was a real pain in the ass to sift through all the different paths. The end result, though, was such a blessing. So, I’ll just point out the interesting paths here. If you ever find yourself in a similar LFI situation, feel free to ask any LLMs for more paths to enumerate (because, honestly, that’s what I did! A lot of the interesting paths were suggested by LLMs, haha).

I first checked `/logs?service=../../../proc/mounts`, which lists mounted services (or whatever they are). This pointed me to `/run/secrets/kubernetes.io/serviceaccount/`, and with this path, I was pretty sure the challenge was related to Kubernetes. So, I started researching Kubernetes since I’m not super familiar with Kubernetes security. I had to read up on the documentation to understand how to access it, especially since all I had was an LFI vulnerability. Most of the blogs I found about accessing Kubernetes involved `kubectl`, and I initially thought it was only useful if you had a shell.

But more research eventually led me to [_this_](https://kubernetes.io/docs/tasks/run-application/access-api-from-pod/#directly-accessing-the-rest-api) particular page in the Kubernetes documentation.

## Token & Certificate
The documentation also pointed out where to find the token and certificate needed to access the pods or secrets in Kubernetes.

`/var/run/secrets/kubernetes.io/serviceaccount/token` contains the JWT token used to authenticate with Kubernetes when accessing it.  
`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` is the internal certificate authority (CA) used for secure communication.

With both of these pieces of information, we could easily use `curl` to enumerate the Kubernetes API:
```
curl --cacert /path/to/ca.crt --header "Authorization: Bearer <JWT-TOKEN>" -X GET <API-SERVER>/api
```

This would allow us to interact with the Kubernetes API server.

# Cloud Part
## Internet Facing Server
Now, the main task was to find or search for the internet-facing Kubernetes API server. While the documentation covered how to access the API directly from within the pods, our focus was on locating the internet-facing API. The documentation provided the following information, which helped me track down the API server.
![](assets/Pasted%20image%2020250127200618.png)

This led me to check the environment variables using the LFI we had. Yay!

I checked the following file: `/logs?service=../../../proc/self/environ` for environment variables, and it had a ton of useful information for this challenge. (Yeah, I didn’t spot the most informative details at first—it took a few hours before I finally saw it.) Anyway, here are a few interesting ones:
```bash
DEV_CLUSTER_ADDR=https://7b9fc16d-5421-47b3-ab64-83dfee3050eb.k8s.ondigitalocean.com
SECRETS_NAMESPACE=secret-namespace
```

The `DEV_CLUSTER_ADDR` pointed me to the Kubernetes cluster's address (The Internet-Facing API), and `SECRETS_NAMESPACE` gave me the namespace for the secrets. 

## Trouble with cURL
I was using `cURL` the whole time with the following command:
```bash
╭─rezy@dev ~  
╰─➤  curl -k -H "Authorization: Bearer <TOKEN>" https://7b9fc16d-5421-47b3-ab64-83dfee3050eb.k8s.ondigitalocean.com/api/v1/                          
{
  "kind": "APIResourceList",
  "groupVersion": "v1",
  "resources": [
    {
      "name": "bindings",
      "singularName": "binding",
      "namespaced": true,
      "kind": "Binding",
      "verbs": [
        "create"
      ]
    },
    {
      "name": "componentstatuses",
      "singularName": "componentstatus",
      "namespaced": false,
      "kind": "ComponentStatus",
      "verbs": [
        "get",
        "list"
      ],
[....//snip//.....]
```

But all I got was a 'forbidden' error when accessing secrets. Then, I discovered that `kubectl` can be used remotely.

## Kubectl Installation
We can find the installation guide for `kubectl` [here](https://kubernetes.io/docs/tasks/tools/).

## Endgame
Then, using the `kubectl` documentation, I ran the following command to list the namespaces/files that the current user (based on the JWT token we have) can access:
```bash
kubectl auth can-i --list \
  --server=https://7b9fc16d-5421-47b3-ab64-83dfee3050eb.k8s.ondigitalocean.com \
  --token=<TOKEN> \
  --certificate-authority=ca.crt \
  --namespace=secret-namespace\
```

This command helped me figure out what I had permission to access.

It will list an interesting resource called `top-secret-flag`. Use the following command to read the secret from `top-secret-flag` in the `secret-namespace` namespace:
```bash
kubectl get secret top-secret-flag \
  --server=https://7b9fc16d-5421-47b3-ab64-83dfee3050eb.k8s.ondigitalocean.com \
  --token=<JWT-TOKEN> \
  --certificate-authority=ca.crt \
  --namespace=secret-namespace \
  -o yaml
```

![](assets/Pasted%20image%2020250127203937.png)

This command lists information, and within it, we find our flag—`TUCTF{3ven_m04r_51lly_d3f4ul75}`—(base64 encoded version though). Decoding it gives us the actual flag, and with that, the challenge is solved!

# Conclusion
Thanks for showing interest in my writeup! It was a fun challenge to solve. We managed to secure 40th position in this CTF, and this particular challenge was my personal favorite—it was a blast giving it a try.
![](assets/Pasted%20image%2020250127204350.png)

I learned a lot about Kubernetes, pods, and namespaces, and it was a great reminder that real learning happens outside of our comfort zones!

Thanks once again! See you in the next writeup! 😄