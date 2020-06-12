# Kadisoka Identity and Access Management Service

Kadisoka IAM is a service module which provides identity and access
management subsystem either as separate service (following microservice
paradigm) or as a library for monolithic service applications.

## Getting Started

This project was designed to use only docker-compose to run locally. Be sure
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
`http://localhost:11111/` from the host.

### Starting the examples

#### Monolithic application example

The monolithic application example is located in `examples/monolith`. To start
it, use where this README.md file is located as the working directory and run
the command:

```shell
docker-compose -f examples/monolith/docker-compose.yaml up --build
```

