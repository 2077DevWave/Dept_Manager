# API Documentation

This API provides functionality for user registration, login, transactions, and managing relationships between users. It is built using the Hono framework and includes CORS middleware for cross-origin requests.

## Base URL
The base URL for the API is `/`.

## Endpoints

### 1. **POST /register**
Register a new user.

#### Request Body
```json
{
  "username": "string",
  "password": "string"
}
```

#### Response
- `201` - User registered successfully.
```json
{
  "message": "User registered successfully"
}
```
- `400` - Invalid content type or invalid JSON body.
- `409` - Username already exists.
- `500` - Server error.

---

### 2. **POST /login**
Log in a user and generate a session token.

#### Request Body
```json
{
  "username": "string",
  "password": "string"
}
```

#### Response
- `200` - Login successful.
```json
{
  "message": "Login successful",
  "username": "string",
  "sessionToken": "string"
}
```
- `400` - Invalid content type or invalid JSON body.
- `401` - Invalid credentials.
- `500` - Server error.

---

### 3. **POST /logout**
Log out the user by deleting the session token.

#### Request Headers
- `Authorization: Bearer <session_token>`

#### Response
- `200` - Logout successful.
```json
{
  "message": "Logout successful"
}
```
- `500` - Server error.

---

### 4. **POST /transactions**
Create a new transaction. Requires authentication.

#### Request Body
```json
{
  "description": "string",
  "payees": [
    {
      "payee_id": "string",
      "share": "number"
    }
  ],
  "type": "string" // optional, defaults to "regular"
}
```

#### Response
- `201` - Transaction created successfully.
```json
{
  "message": "Transaction created successfully",
  "tx_id": "string"
}
```
- `400` - Invalid or missing fields.
- `500` - Server error.

---

### 5. **GET /transactions/:tx_id**
Get transaction details by ID. Requires authentication.

#### Response
- `200` - Transaction details retrieved.
```json
{
  "tx_id": "string",
  "creditor_id": "string",
  "description": "string",
  "type": "string",
  "created_at": "string",
  "payees": [
    {
      "payee_id": "string",
      "share": "number",
    }
  ]
}
```
- `404` - Transaction not found.
- `500` - Server error.

---

### 6. **DELETE /transactions/:tx_id**
Delete a transaction by ID. Requires authentication.

#### Response
- `200` - Transaction deleted successfully.
```json
{
  "message": "Transaction deleted successfully"
}
```
- `500` - Server error.

---

### 7. **POST /known-persons**
Add a user as a known person. Requires authentication.

#### Request Body
```json
{
  "known_user_id": "string"
}
```

#### Response
- `201` - User added as a known person successfully.
```json
{
  "message": "User added as known person successfully"
}
```
- `400` - Invalid or missing fields.
- `500` - Server error.

---

### 8. **GET /known-persons**
Get all users known by the authenticated user.

#### Response
- `200` - List of known persons.
```json
{
  "known_persons": [
    {
      "id": "string",
      "username": "string"
    }
  ]
}
```
- `500` - Server error.

---

### 9. **GET /transactions**

**Description**:  
Retrieves all transactions for the authorized user, including both as a creditor and a payee. The response is split into two categories: transactions where the user is the creditor and transactions where the user is the payee.

**Authentication**:  
This endpoint requires the user to be authenticated. A valid session token is necessary to access the data.

**Request**:
- **Method**: GET
- **Path**: `/transactions`
- **Headers**:  
  - `Authorization: Bearer <session_token>`

**Response**:
- **Success (200 OK)**:
  ```json
  {
      "creditor_transactions": [
          {
              "tx_id": "<transaction_id>",
              "creditor_id": "<creditor_id>",
              "amount": "<amount>",
              "date": "<date>",
              "payees": [
                  {
                      "payee_id": "<payee_id>",
                      "share": "<share_amount>",
                  },
                  ...
              ]
          },
          ...
      ],
      "payee_transactions": [
          {
              "tx_id": "<transaction_id>",
              "creditor_id": "<creditor_id>",
              "amount": "<amount>",
              "date": "<date>",
              "payees": [
                  {
                      "payee_id": "<payee_id>",
                      "share": "<share_amount>",
                  },
                  ...
              ]
          },
          ...
      ]
  }
  ```
  - **creditor_transactions**: A list of transactions where the user is the creditor. Each transaction includes the details of the transaction, including a list of payees with their respective shares and paid status.
  - **payee_transactions**: A list of transactions where the user is a payee. Each transaction includes the details of the transaction and the creditor details.

- **Error (500 Internal Server Error)**:
  ```json
  {
      "error": "Server error"
  }
  ```

**Notes**:
- The payee information is returned as a JSON string in the `payees` field, which is parsed into an array of objects, each containing the `payee_id`, `share`, and `paid` status for each payee.
- If there are no transactions for the user, both the `creditor_transactions` and `payee_transactions` arrays will be empty.

---

### 10. **GET /search-users**
Search users by username. Requires authentication.

#### Request Parameters
- `username` (required)

#### Response
- `200` - List of users matching the username.
```json
{
  "users": [
    {
      "id": "string",
      "username": "string"
    }
  ]
}
```
- `400` - Missing `username` query parameter.
- `500` - Server error.

---

### 11. **GET /users/:userId**
Get user details by ID. Requires authentication.

#### Response
- `200` - User details retrieved.
```json
{
  "id": "string",
  "username": "string",
  "created_at": "string"
}
```
- `404` - User not found.
- `500` - Server error.

---

## CORS Middleware
CORS is enabled for all endpoints, with the following configuration:
- **Origins**: `*` (allow all origins)
- **Allowed Methods**: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`
- **Allowed Headers**: `Content-Type`, `Authorization`
- **Exposed Headers**: `Content-Length`
- **Credentials**: `true` (allow cookies and authorization headers)
- **Max Age**: `86400` seconds (1 day)

---

## Authentication
Most endpoints require the user to be logged in. To authenticate:
- Include a session token in the `Authorization` header as `Bearer <session_token>`.
- Use the `/login` endpoint to obtain a session token.

---

## Error Handling
- **400** - Bad Request: The request is invalid (e.g., missing or incorrect fields).
- **401** - Unauthorized: The user is not authenticated or session is invalid.
- **404** - Not Found: The requested resource does not exist.
- **500** - Internal Server Error: An unexpected error occurred on the server.

---

This documentation covers the basic usage of the API for user management, transactions, and relationships between users.