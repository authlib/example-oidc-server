# Example of OpenID Connect 1.0 Provider

This is an example of OpenID Connect 1.0 server in Flask and [Authlib](https://authlib.org/).

- Documentation: <https://docs.authlib.org/en/latest/flask/2/>
- Authlib Repo: <https://github.com/lepture/authlib>

---

## Take a quick look

This is a ready to run example, let's take a quick experience at first. To
run the example, we need to install all the dependencies:

    $ pip install -r requirements.txt

Set Flask and Authlib environment variables:

    # disable check https (DO NOT SET THIS IN PRODUCTION)
    $ export AUTHLIB_INSECURE_TRANSPORT=1

Create Database and run the development server:

    $ flask initdb
    $ flask run

Now, you can open your browser with `http://127.0.0.1:5000/`, login with any
name you want.

Before testing, we need to create a client:

![create a client](https://user-images.githubusercontent.com/290496/64176341-35888100-ce98-11e9-8395-fd4cdc029fd2.png)

**NOTE: YOU MUST ADD `openid` SCOPE IN YOUR CLIENT**

Let's take `authorization_code` grant type as an example. Visit:

```
http://127.0.0.1:5000/oauth/authorize?client_id=${CLIENT_ID}&scope=openid+profile&response_type=code&nonce=abc
```

After that, you will be redirect to a URL. For instance:

```
https://example.com/?code=RSv6j745Ri0DhBSvi2RQu5JKpIVvLm8SFd5ObjOZZSijohe0
```

Copy the code value, use `curl` to get the access token:

```
curl -u "${CLIENT_ID}:${CLIENT_SECRET}" -XPOST http://127.0.0.1:5000/oauth/token -F grant_type=authorization_code -F code=RSv6j745Ri0DhBSvi2RQu5JKpIVvLm8SFd5ObjOZZSijohe0
```

Now you can access the userinfo endpoint:

```bash
$ curl -H "Authorization: Bearer ${access_token}" http://127.0.0.1:5000/oauth/userinfo
```
