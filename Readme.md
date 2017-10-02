# JohannesSteu.JwtAuth

This package is a simple demo how to implement a jwt authentication in Neos Flow.
For more details about the JSON Web token itself check https://jwt.io/introduction/.

This mechanism is a great choice to sign for api requests in flow.

### This package contains

#### JwtToken
This class represents a JWT token. This token contains the JWT string wich is sent in your request. The JWT string must be provided in a `X-JWT` Header.
The payload itself must contain a property `accountIdentifier`.

##### JwtTokenProvider
The JwtTokenProvider validates a JwtToken. It will first check if the token contains a jwt string at all and then try to decode it with a configured shared secret. If the payload can be decoded it will create a transient account with the data from the payload and set this account as authenticated.



#### Access data from the payload in flow
This demo implementation will set the full payload into the authenticated token. To access the data
in your flow application:

```
$authenticationToken = $this->securityContext->getAuthenticationTokensOfType(JwtToken::class)[0];
$jwtPayload = $authenticationToken->getPayload();
```

##### Example Request
This is a valid request and will be authenticated with the role `JohannesSteu.JwtAuth:User` in flow:


```
curl -H "X-JWT=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50SWRlbnRpZmllciI6InNvbWUtYWNjb3VudCIsIm5hbWUiOiJKb2huIERvZSJ9.8slTfTqCRozgcby-As6KxeCb5Zq9zX3TmVUcJAgW328" http://your-app.com
```

To debug the jwt string [click here.](https://jwt.io/#debugger?&id_token=https://jwt.io/#debugger?&id_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50SWRlbnRpZmllciI6InNvbWUtYWNjb3VudCIsIm5hbWUiOiJKb2huIERvZSJ9.8slTfTqCRozgcby-As6KxeCb5Zq9zX3TmVUcJAgW328)
Enter the shared secret `aSharedSecret` to verify the signature.
