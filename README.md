JWKS Server made in Go for CSCE 3550, made very last minute with the aid of ChatGPT and Gemini.

For project 3 it is possible it will be remade in JavaScript, God Willing

The links to the chats used are here:

    ChatGPT: https://chatgpt.com/share/67b280c5-4464-800e-aaa4-e4e348afce58
              //This one is a continuation of a previous chat that I cannot link for some reason -- the first prompt from that initial chat is below

    Gemini: https://g.co/gemini/share/0f289b9194d3

The AI's were mainly used to set up the general format of the server and to help with problem solving, bug-fixing, and general clarification. I did not intend to use AI to this degree, but I decided to procrastinate instead of working on this assignment.
In the end I found the concept quite interesting, and did learn quite a bit whilst working on it. Go is not too bad of a language, and I got tired of all the JavaScript related installations I would need to get the server working. If specific prompts from the chats need to be listed, I can add them here, but most of them are me and the AI failing to communicate with each other except via lengthy error blocks.

The initial prompt was the core requirements for the server:

      "Implementing a basic JWKS Server
      Objective
      Develop a RESTful JWKS server that provides public keys with unique identifiers (kid) for verifying JSON Web Tokens (JWTs), implements key expiry for enhanced security, includes an authentication endpoint, and handles the issuance of JWTs with expired keys based on a query parameter.

      Chooses an appropriate language and web server for the task.

      Due to the simplicity of this assignment, I would prefer you complete it with an unfamiliar language… but as I have no way to verify it, it’s not considered part of the rubric.

      This project is for educational purposes. In a real-world scenario, you’d want to integrate with a proper authentication system and ensure security best practices.                           Requirements
      Key Generation
      Implement RSA key pair generation.
      Associate a Key ID (kid) and expiry timestamp with each key.
      Web server with two handlers
      Serve HTTP on port 8080
      A RESTful JWKS endpoint that serves the public keys in JWKS format.
      Only serve keys that have not expired.
      A /auth endpoint that returns an unexpired, signed JWT on a POST request.
      If the “expired” query parameter is present, issue a JWT signed with the expired key pair and the expired expiry.
      Documentation
      Code should be organized.
      Code should be commented where needed.
      Code should be linted per your language/framework.
      Tests
      Test suite for your given language/framework with tests for you.
      Test coverage should be over 80%.
      Blackbox testing
      Ensure the included test clientLinks to an external site. functions against your server.
      The testing client will attempt a POST to /auth with no body. There is no need to check authentication for this project.
      NOTE: We are not actually testing user authentication, just mocking authentication and returning a valid JWT for this user
      Note:
      Using kid in JWKS is crucial for systems to identify which key to use for JWT verification. Ensure that the JWTs include the kid in their headers and that the JWKS server can serve the correct key when requested with a specific kid. "

To note, and while it is most likely an issue on my end, I kept failing these two sections of the Gradebot no matter what I changed:

      time=2025-02-16T18:43:25.251-06:00 level=ERROR msg="Valid JWK found in JWKS" err="JWKS: failed to extract response via extractor function: invalid HTTP status code: 404"
      time=2025-02-16T18:43:25.254-06:00 level=ERROR msg="Expired JWK does not exist in JWKS" err="JWKS error: failed to extract response via extractor function: invalid HTTP status code: 404"




