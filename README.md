# Citadelium Identity and Access Management Service

Citadelium IAM is a service module which provides identity and access
management subsystem either as separate service (following microservice
paradigm) or as a library for monolithic service applications.

## Getting Started

This project was designed to use only docker-compose to run locally. Be sure
to have Docker and docker-compose installed. Go binary distribution is not
required to be installed on the host.

The root `docker-compose.yaml` file was designed to run the server application
which source and its required resources are located in folder `iam-server`.

To start the server:

```shell
docker-compose up --build
```

This command will build and set up third party services required to run
`iam-server`.
