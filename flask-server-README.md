# Flask Web Server

Simple Flask web server with three endpoints for testing and demonstration purposes.

## Endpoints

### 1. GET /
Returns a welcome message with current timestamp.

**Response:**
```json
{
  "message": "Welcome to CoreFlow360 V4 Flask Server",
  "timestamp": "2025-10-04T12:00:00.000000"
}
```

### 2. GET /health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-04T12:00:00.000000"
}
```

### 3. POST /echo
Echoes back the JSON data with an added timestamp field.

**Request:**
```json
{
  "name": "John",
  "message": "Hello World"
}
```

**Response:**
```json
{
  "name": "John",
  "message": "Hello World",
  "timestamp": "2025-10-04T12:00:00.000000"
}
```

## Setup and Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the server:
```bash
python app.py
```

The server will start on `http://localhost:5000`

## Testing the Endpoints

### Using curl:

```bash
# Test welcome endpoint
curl http://localhost:5000/

# Test health check
curl http://localhost:5000/health

# Test echo endpoint
curl -X POST http://localhost:5000/echo \
  -H "Content-Type: application/json" \
  -d '{"name": "John", "message": "Hello World"}'
```

### Using Python requests:

```python
import requests

# Test welcome endpoint
response = requests.get('http://localhost:5000/')
print(response.json())

# Test health check
response = requests.get('http://localhost:5000/health')
print(response.json())

# Test echo endpoint
response = requests.post('http://localhost:5000/echo',
                        json={'name': 'John', 'message': 'Hello World'})
print(response.json())
```

## Features

- JSON responses for all endpoints
- Proper error handling (400, 404, 500)
- Logging for all requests and errors
- Timestamp tracking
- Content-Type validation for POST requests
