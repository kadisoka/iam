# Kadisoka Identity Server Module

Kadisoka IAM is a service module which provides identity and access
management subsystem either as separate service (following microservice
paradigm) or as a library for monolithic service applications.

## Features

* Flexible deployment: standalone service or as a module for your Go application
* OAuth 2.0 conforming authorization server
* Web UI which provides good user experience. We want that out of the box,
  this project provides not only functional, but also good experience for
  the users.
* Online and always up-to-date REST API documentation.
* SMS delivery service integrations (for delivering the OTPs): Vonage (Nexmo),
  Telesign, Twilio
* Email delivery service integrations (for delivering the OTPs): Amazon SES
* Database system support: PostgreSQL

## Getting Started

This project was designed to use only
[docker-compose](https://docs.docker.com/compose/) to run locally. Be sure
to have Docker and docker-compose installed. Go binary distribution is not
required to be installed on the host.

The root `docker-compose.yaml` file was designed to run the independent server
application which source and its required resources are located in folder
`iam-server`. Once started, user and other applications could connect to it.

To start the server:

```shell
docker-compose up --build
```

Once started, the user-facing web UI could be accessed at
`http://localhost:11111/` from the host. The REST API documentation could
be accessed at `http://localhost:11121/rest/apidocs/`.

### Starting the examples

#### Monolithic application example

The monolithic application example is located in `examples/monolith`. To start
it, use where this README.md file is located as the working directory and run
the command:

```shell
docker-compose -f examples/monolith/docker-compose.yaml up --build
```

## Use cases

### Identity server mock

As your projects are integrated to other identity management service, you
would need to test the integrations. This project could be used as a mock of
the identity server your projects depended on.

### Monolithic service applications

If your application is relatively small in scale, like a simple online shop,
a CMS, or a blog, you could import this module into your application to
provide user account management for your application.

Monolithic architecture is preferable if your service is relatively small as
it's easier to maintain. If your application is getting popular, you can
transition to microservice architecture with minimum effort.

