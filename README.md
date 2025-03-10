# Recipe API Documentation

## Overview
This API allows users to register, log in, and manage their recipes securely. The API includes authentication, rate-limiting, and CRUD operations for recipe management.

## Base URL
```
https://recipes-api-green.vercel.app/api
```

## Authentication
All protected endpoints require a Bearer token in the Authorization header.
```
Authorization: Bearer <token>
```

---
## Endpoints

### 1. User Registration
**Endpoint:**
```
POST /api/register
```
**Request Body:**
```json
{
  "username": "exampleUser",
  "password": "examplePass"
}
```
**Response:**
```json
{
  "message": "User registered successfully"
}
```

### 2. User Login
**Endpoint:**
```
POST /api/login
```
**Request Body:**
```json
{
  "username": "exampleUser",
  "password": "examplePass"
}
```
**Response:**
```json
{
  "token": "your-jwt-token"
}
```

---
### 3. Create a Recipe (Protected)
**Endpoint:**
```
POST /api/recipes
```
**Headers:**
```
Authorization: Bearer <token>
```
**Request Body:**
```json
{
  "title": "Spaghetti Carbonara",
  "description": "A classic Italian pasta dish",
  "items": ["pasta", "eggs", "cheese", "bacon"],
  "cookingTime": 30,
  "category": "Main Course",
  "image": "image-url"
}
```
**Response:**
```json
{
  "_id": "recipeId",
  "title": "Spaghetti Carbonara",
  "description": "A classic Italian pasta dish",
  "items": ["pasta", "eggs", "cheese", "bacon"],
  "cookingTime": 30,
  "category": "Main Course",
  "image": "image-url",
  "userId": "userId",
  "isSystem": false
}
```

---
### 4. Get All Recipes (Protected)
**Endpoint:**
```
GET /api/recipes
```
**Headers:**
```
Authorization: Bearer <token>
```
**Response:**
```json
[
  {
    "_id": "recipeId",
    "title": "Spaghetti Carbonara",
    "description": "A classic Italian pasta dish",
    "items": ["pasta", "eggs", "cheese", "bacon"],
    "cookingTime": 30,
    "category": "Main Course",
    "image": "image-url",
    "userId": "userId",
    "isSystem": false
  }
]
```

---
### 5. Get a Recipe by ID (Protected)
**Endpoint:**
```
GET /api/recipes/:id
```
**Headers:**
```
Authorization: Bearer <token>
```
**Response:**
```json
{
  "_id": "recipeId",
  "title": "Spaghetti Carbonara",
  "description": "A classic Italian pasta dish",
  "items": ["pasta", "eggs", "cheese", "bacon"],
  "cookingTime": 30,
  "category": "Main Course",
  "image": "image-url",
  "userId": "userId",
  "isSystem": false
}
```

---
### 6. Filter Recipes by Name (Protected)
**Endpoint:**
```
GET /api/recipes/filter?name=<query>
```
**Headers:**
```
Authorization: Bearer <token>
```
**Response:**
```json
[
  {
    "_id": "recipeId",
    "title": "Spaghetti Carbonara",
    "description": "A classic Italian pasta dish",
    "items": ["pasta", "eggs", "cheese", "bacon"],
    "cookingTime": 30,
    "category": "Main Course",
    "image": "image-url",
    "userId": "userId",
    "isSystem": false
  }
]
```

---
### 7. Update a Recipe (Protected)
**Endpoint:**
```
PUT /api/recipes/:id
```
**Headers:**
```
Authorization: Bearer <token>
```
**Request Body:**
```json
{
  "title": "Updated Recipe Title"
}
```
**Response:**
```json
{
  "_id": "recipeId",
  "title": "Updated Recipe Title",
  "description": "Updated description",
  "items": ["updated items"],
  "cookingTime": 30,
  "category": "Main Course",
  "image": "updated-image-url",
  "userId": "userId",
  "isSystem": false
}
```

---
### 8. Delete a Recipe (Protected)
**Endpoint:**
```
DELETE /api/recipes/:id
```
**Headers:**
```
Authorization: Bearer <token>
```
**Response:**
```json
{
  "message": "Recipe deleted successfully"
}
```

---
## Rate Limiting
Users are limited to **3000 requests per day**. When the limit is reached, the API returns:
```json
{
  "error": "Daily request limit exceeded",
  "limit": 3000,
  "remaining": 0
}
```

## Error Handling
Standard error responses include:
- **400 Bad Request:** Missing or invalid parameters
- **401 Unauthorized:** Invalid or missing token
- **403 Forbidden:** Token verification failure
- **404 Not Found:** Resource does not exist
- **429 Too Many Requests:** Rate limit exceeded

## Notes
- System recipes (isSystem = true) cannot be updated or deleted by users.
- Tokens expire in 1 hour.

