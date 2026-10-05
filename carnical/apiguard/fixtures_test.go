// SPDX-License-Identifier: Apache-2.0

package apiguard

// shopAPI is an OpenAPI 3.0.3 description of the kind a small shop would have: path and query parameters, references into
// components, an allOf, enums, read-only properties, a closed object, two security schemes.
const shopAPI = `{
  "openapi": "3.0.3",
  "info": {"title": "Shop API", "version": "1.4.0"},
  "servers": [{"url": "https://shop.example.test/api/v1"}],
  "security": [{"bearer": []}],
  "paths": {
    "/products": {
      "get": {
        "operationId": "listProducts",
        "security": [],
        "parameters": [
          {"$ref": "#/components/parameters/limit"},
          {"name": "page", "in": "query", "schema": {"type": "integer", "minimum": 1}},
          {"name": "sort", "in": "query", "schema": {"type": "string", "enum": ["name", "price", "-price"]}},
          {"name": "q", "in": "query", "schema": {"type": "string", "maxLength": 50}},
          {"name": "tags", "in": "query", "explode": false, "schema": {"type": "array", "items": {"type": "string"}, "maxItems": 3}}
        ],
        "responses": {"200": {"description": "ok"}}
      },
      "post": {
        "operationId": "createProduct",
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProductCreate"}}}},
        "responses": {"201": {"description": "created"}}
      }
    },
    "/products/{id}": {
      "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer", "minimum": 1}}],
      "get": {"security": [], "responses": {"200": {"description": "ok"}}},
      "put": {
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ProductCreate"}}}},
        "responses": {"200": {"description": "ok"}}
      },
      "delete": {"responses": {"204": {"description": "gone"}}}
    },
    "/products/{id}/reviews": {
      "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}],
      "get": {"security": [], "responses": {"200": {"description": "ok"}}},
      "post": {
        "requestBody": {"content": {"application/json": {"schema": {"type": "object", "required": ["stars"], "properties": {"stars": {"type": "integer", "minimum": 1, "maximum": 5}, "text": {"type": "string", "maxLength": 2000}}}}}},
        "responses": {"201": {"description": "created"}}
      }
    },
    "/users": {
      "post": {
        "security": [],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Registration"}}}},
        "responses": {"201": {"description": "created"}}
      }
    },
    "/users/{userId}": {
      "parameters": [{"name": "userId", "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}}],
      "get": {"responses": {"200": {"description": "ok"}}},
      "patch": {
        "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/UserUpdate"}}}},
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/auth/login": {
      "post": {
        "security": [],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["email", "password"], "additionalProperties": false, "properties": {"email": {"type": "string", "format": "email"}, "password": {"type": "string", "minLength": 8}}}}}},
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/orders/{orderId}": {
      "get": {
        "parameters": [{"name": "orderId", "in": "path", "required": true, "schema": {"type": "string", "pattern": "^[A-Z]{2}-[0-9]{6}$"}}, {"name": "X-Shop-Key", "in": "header", "required": true, "schema": {"type": "string", "minLength": 8}}],
        "responses": {"200": {"description": "ok"}}
      }
    },
    "/export": {"get": {"security": [], "responses": {"200": {"description": "csv", "content": {"text/csv": {}}}}}}
  },
  "components": {
    "securitySchemes": {
      "bearer": {"type": "http", "scheme": "bearer"},
      "shopkey": {"type": "apiKey", "in": "header", "name": "X-Shop-Key"}
    },
    "parameters": {
      "limit": {"name": "limit", "in": "query", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20}}
    },
    "schemas": {
      "Money": {"type": "number", "minimum": 0, "multipleOf": 0.01},
      "Product": {
        "type": "object",
        "required": ["name", "price"],
        "properties": {"id": {"type": "integer", "readOnly": true}, "name": {"type": "string", "minLength": 1, "maxLength": 80}, "price": {"$ref": "#/components/schemas/Money"}, "stock": {"type": "integer", "minimum": 0}}
      },
      "ProductCreate": {
        "allOf": [{"$ref": "#/components/schemas/Product"}, {"type": "object", "properties": {"category": {"type": "string", "enum": ["toys", "books", "tools"]}, "note": {"type": "string", "nullable": true}}}]
      },
      "Registration": {
        "type": "object", "required": ["email", "password"], "additionalProperties": false,
        "properties": {"email": {"type": "string", "format": "email"}, "password": {"type": "string", "minLength": 8, "maxLength": 100}, "name": {"type": "string", "maxLength": 80}}
      },
      "UserUpdate": {
        "type": "object", "additionalProperties": false,
        "properties": {"id": {"type": "string", "readOnly": true}, "role": {"type": "string", "readOnly": true}, "name": {"type": "string", "maxLength": 80}, "email": {"type": "string", "format": "email"}}
      }
    }
  }
}`

// petStoreYAML is a Swagger 2.0 description in YAML: inline parameter types, a body parameter, basePath, consumes, definitions.
const petStoreYAML = `swagger: "2.0"
info:
  title: Pet store
  version: "1.0"
basePath: /v2
consumes:
  - application/json
securityDefinitions:
  api_key:
    type: apiKey
    name: api_key
    in: header
paths:
  /pet:
    post:
      security:
        - api_key: []
      parameters:
        - in: body
          name: body
          required: true
          schema:
            $ref: "#/definitions/Pet"
      responses:
        "200":
          description: ok
  /pet/{petId}:
    get:
      parameters:
        - name: petId
          in: path
          required: true
          type: integer
          format: int64
          minimum: 1
        - name: verbose
          in: query
          type: boolean
      responses:
        "200":
          description: ok
    delete:
      parameters:
        - name: petId
          in: path
          required: true
          type: integer
      responses:
        "400":
          description: bad
  /pet/findByStatus:
    get:
      parameters:
        - name: status
          in: query
          required: true
          type: array
          collectionFormat: csv
          items:
            type: string
            enum: [available, pending, sold]
      responses:
        "200":
          description: ok
  /pet/{petId}/uploadImage:
    post:
      consumes:
        - multipart/form-data
      parameters:
        - name: petId
          in: path
          required: true
          type: integer
        - name: file
          in: formData
          type: file
      responses:
        "200":
          description: ok
definitions:
  Category:
    type: object
    properties:
      id: {type: integer}
      name: {type: string}
  Pet:
    type: object
    required: [name]
    properties:
      id: {type: integer, readOnly: true}
      category:
        $ref: "#/definitions/Category"
      name: {type: string, minLength: 1}
      status: {type: string, enum: [available, pending, sold]}
`

// oas31YAML is OpenAPI 3.1 in YAML: type arrays, const, numeric exclusiveMinimum, a webhook that is ignored, a self-referencing
// schema (a tree).
const oas31YAML = `openapi: 3.1.0
info:
  title: Tree
  version: "1"
paths:
  /nodes/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema: {type: integer, exclusiveMinimum: 0}
    get:
      responses: {"200": {description: ok}}
    put:
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Node"}
      responses: {"200": {description: ok}}
components:
  schemas:
    Node:
      type: object
      required: [kind]
      additionalProperties: false
      properties:
        kind: {const: node}
        label: {type: [string, "null"], maxLength: 20}
        children:
          type: array
          items: {$ref: "#/components/schemas/Node"}
webhooks:
  ping:
    post:
      responses: {"200": {description: ok}}
`
