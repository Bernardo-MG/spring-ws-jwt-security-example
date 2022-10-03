# Spring WS JWT Security Example

Example for JWT security with Spring.

## Usage

As this is a Spring Boot app it may be run with Maven or through your preferred IDE.

```
mvn spring-boot:run
```

Once running the web service will be available at [http://localhost:8080/](http://localhost:8080/).

### Requests with Postman

Import `src/test/resources/jwt_auth.postman_collection.json` to get queries for all the operations including authentication.

### Users

| User     | Password | Permissions    |
|----------|----------|----------------|
| admin    | 1234     | all            |
| noroles  | 1111     | none           |
| locked   | 1111     | all            |
| expired  | 1111     | all            |
| disabled | 1111     | all            |
| expcreds | 1111     | all            |
| noread   | 1111     | all minus read |
