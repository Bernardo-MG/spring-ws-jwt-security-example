# Spring WS JWT Security Example

Example for setting up JWT HTTP Security on a web service with Spring Boot.

## Usage

Just run it as any Spring boot application:

```
mvn spring-boot:run
```

And the web service be available at [http://localhost:8080/](http://localhost:8080/).

## Requests with Postman

To make things easier import `src/test/resources/jwt_auth.postman_collection.json` into Postman. It includes all the queries needed to test the project.

## Users

| User     | Password | Permissions    |
|----------|----------|----------------|
| admin    | 1234     | all            |
| noroles  | 1111     | none           |
| locked   | 1111     | all            |
| expired  | 1111     | all            |
| disabled | 1111     | all            |
| expcreds | 1111     | all            |
| noread   | 1111     | all minus read |

## Database

All the data is stored in a H2 in-memory database.

