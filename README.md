# JM API Gateway

API Gateway for routing requests and validating JWT tokens.

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│  Frontend   │────►│   API Gateway   │────►│   Eureka    │
│  (Vercel)   │     │   (Render VM)   │     │ (Render VM) │
└─────────────┘     └─────────────────┘     └─────────────┘
                            │
                            ▼
                    ┌─────────────┐
                    │    Redis    │
                    │  (Render)   │
                    └─────────────┘
```

---

## Project Structure

```
api-gateway/
├── Dockerfile                 # Docker build instructions for Render
├── pom.xml                    # Maven dependencies (multi-module)
├── pom-standalone.xml         # Maven dependencies (standalone for Render)
├── render.yaml                # Render deployment configuration
├── .gitignore                 # Files to ignore in git
├── README.md                  # This file
└── src/main/
    ├── java/com/devision/jm/gateway/
    │   ├── ApiGatewayApplication.java     # Main Spring Boot entry point
    │   ├── config/
    │   │   ├── CorsConfig.java            # CORS settings - which frontends can access
    │   │   ├── RedisConfig.java           # Redis connection for token revocation
    │   │   └── RouteConfig.java           # API routes - maps URLs to services
    │   ├── filter/
    │   │   ├── AuthenticationFilter.java  # JWT token validation
    │   │   ├── InternalApiKeyFilter.java  # Service-to-service authentication
    │   │   ├── LoggingFilter.java         # Request/response logging
    │   │   └── RateLimitingFilter.java    # Prevents too many requests
    │   ├── controller/
    │   │   └── FallbackController.java    # Responses when services are down
    │   └── exception/
    │       ├── GlobalExceptionHandler.java # Handles errors globally
    │       └── UnauthorizedException.java  # 401 error class
    └── resources/
        ├── application.yml                # Default configuration
        └── application-render.yml         # Render-specific configuration
```

### File Explanations

| File | Purpose |
|------|---------|
| `Dockerfile` | Builds the Java app into a Docker container for Render |
| `pom-standalone.xml` | Maven build file without parent dependency (for Render) |
| `render.yaml` | Tells Render how to deploy this service |
| `CorsConfig.java` | Controls which frontend URLs can call this API |
| `RouteConfig.java` | Maps `/api/v1/auth/**` → AUTH-SERVICE, etc. |
| `AuthenticationFilter.java` | Validates JWT tokens on protected routes |
| `application.yml` | Database, Eureka, Redis connection settings |
| `application-render.yml` | Overrides for Render deployment |

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `EUREKA_HOST` | Eureka server URL (no http://) | `jm-eureka.onrender.com` |
| `EUREKA_USERNAME` | Eureka basic auth username | `eureka` |
| `EUREKA_PASSWORD` | Eureka basic auth password | `your-password` |
| `REDIS_HOST` | Redis server hostname | `oregon-redis.render.com` |
| `REDIS_PORT` | Redis port | `6379` |
| `JWT_SECRET` | JWT secret (min 256 bits) | `your-long-secret-key` |
| `CORS_ALLOWED_ORIGINS` | Frontend URL(s) | `https://jm-app.vercel.app` |

---

## Connecting to Eureka (Separate VM)

Set these environment variables to connect to your Eureka server:

```bash
EUREKA_HOST=jm-eureka.onrender.com
EUREKA_USERNAME=eureka
EUREKA_PASSWORD=your-eureka-password
```

The gateway will connect to:
```
http://eureka:password@jm-eureka.onrender.com:8761/eureka/
```

---

## Connecting to Redis

```bash
REDIS_HOST=oregon-redis.render.com
REDIS_PORT=6379
```

---

## Connecting Frontend (CORS)

```bash
CORS_ALLOWED_ORIGINS=https://jm-frontend.vercel.app
```

---

## Deploy to Render

1. Push `api-gateway` folder to GitHub
2. Create **Web Service** on Render
3. Set environment variables in Render dashboard

| Variable | Value |
|----------|-------|
| `SPRING_PROFILES_ACTIVE` | `render` |
| `EUREKA_HOST` | `jm-eureka.onrender.com` |
| `EUREKA_USERNAME` | `eureka` |
| `EUREKA_PASSWORD` | `your-password` |
| `REDIS_HOST` | `your-redis.render.com` |
| `JWT_SECRET` | `your-256-bit-secret` |
| `CORS_ALLOWED_ORIGINS` | `https://your-frontend.vercel.app` |

---

## Health Check

```bash
curl https://your-gateway.onrender.com/actuator/health
```
