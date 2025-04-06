# OpenID Connect Setup Guide

- Docker must be installed

---

1. Run Keycloak using Docker:

   Set up an identity provider with:

   ```bash
   docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:21.1.0 start-dev

2. Configure Client

    **General Settings**  
    Client Type: OpenID Connect  
    Client ID: openid-connect-client  
    
    **Capability Config**  
    Make sure that “Client authentication” is on.  
    
    **Login Settings**  
    Valid redirect URI: http://localhost:5000/auth/callback

   **Credentials**  
   Client Secret must be set in appsettings.Development.json

3. Run Application

   Login with username: admin and password: admin

   
