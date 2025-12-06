# JM API Gateway - User Manual

## Overview

The API Gateway automatically routes requests to any service registered with Eureka. No code changes needed when new services are added.

---

## How Auto-Discovery Works

```
1. Service registers with Eureka
           ↓
2. Gateway fetches service list from Eureka
           ↓
3. Gateway creates route: /{service-name}/** → Service
           ↓
4. Requests to /{service-name}/path are forwarded automatically
```

### Example

JA team deploys `ja-application-service` and registers with Eureka:

```
https://gateway.onrender.com/ja-application-service/api/v1/apply
                              └──────────┬─────────┘└─────┬─────┘
                                 service name         endpoint
```

The gateway automatically forwards this to `ja-application-service`.

---

## URL Pattern

```
https://{gateway-url}/{service-name}/{path}
```

| Service in Eureka | Gateway URL |
|-------------------|-------------|
| `AUTH-SERVICE` | `/auth-service/**` |
| `JOB-SERVICE` | `/job-service/**` |
| `JA-APP-SERVICE` | `/ja-app-service/**` |

---

## Authentication

All routes require JWT authentication **except** public endpoints.

### Public Endpoints (No Auth Required)

Configured in `application.yml`:

```yaml
gateway:
  public-endpoints:
    - /actuator/health
    - /actuator/info
    - /auth-service/api/v1/auth/login
    - /auth-service/api/v1/auth/register
    - /job-service/api/v1/jobs/public/**
```

### Adding New Public Endpoints

Edit `application.yml` and add the path:

```yaml
gateway:
  public-endpoints:
    - /new-service/public/endpoint/**   # Add here
```

No code changes. No redeployment of other services.

---

## For Other Teams (JA, etc.)

### Step 1: Register with Eureka

Add to your service's config:

```yaml
eureka:
  client:
    service-url:
      defaultZone: http://eureka:password@jm-eureka.onrender.com:8761/eureka/
```

### Step 2: Your Service is Now Accessible

```
https://jm-gateway.onrender.com/{your-service-name}/{your-endpoint}
```

### Step 3: Request Public Endpoints (Optional)

Ask JM team to add your public endpoints to `application.yml`:

```yaml
gateway:
  public-endpoints:
    - /your-service/public/**
```

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `EUREKA_HOST` | Eureka server hostname | `jm-eureka.onrender.com` |
| `EUREKA_USERNAME` | Eureka username | `eureka` |
| `EUREKA_PASSWORD` | Eureka password | `your-password` |
| `REDIS_HOST` | Redis hostname | `redis.onrender.com` |
| `JWT_SECRET` | JWT signing secret | `your-256-bit-secret` |
| `CORS_ALLOWED_ORIGINS` | Frontend URL | `https://app.vercel.app` |

---

## Health Check

```bash
curl https://your-gateway.onrender.com/actuator/health
```

---

## Quick Reference

| Action | How |
|--------|-----|
| Add new service | Register with Eureka → Auto-discovered |
| Add public endpoint | Edit `application.yml` → `gateway.public-endpoints` |
| Check registered services | Visit Eureka dashboard |
| Test gateway | `curl /actuator/health` |
