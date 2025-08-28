# 🔐 JWT Authentication + Refresh Flow

```mermaid
sequenceDiagram
    participant U as User
    participant A as Auth Service
    participant DB as Token DB
    participant API as API/Gateway

    U->>A: Login (username/password or Google OAuth)
    A->>DB: Store Refresh Token
    A->>U: Return Access Token + Set Refresh Cookie

    U->>API: Call API with Access Token
    API->>API: Validate Access Token (signature, expiry)

    alt Access Token valid
        API->>U: Return data ✅
    else Access Token expired
        U->>A: Send Refresh Token (cookie)
        A->>A: Validate Refresh Token (signature, claims)
        A->>DB: Check if exists & not revoked
        alt Valid
            A->>DB: Revoke old refresh token
            A->>DB: Save new refresh token
            A->>U: Return new Access Token + new Refresh Cookie
        else Invalid/Revoked
            A->>U: 401 Unauthorized ❌
        end
    end

    U->>A: Logout
    A->>DB: Revoke all refresh tokens
