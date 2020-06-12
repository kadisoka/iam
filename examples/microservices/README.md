# Microservice Example

This folder contains an example of using Kadisoka IAM service in a
microservice configuration. We run Kadisoka IAM service on its own, and
we create another service, contained in this folder, which depended on
Kadisoka IAM service.

This example specifically uses the 3-legged authorization for the users,
while the backend service itself authenticates as a non-user-representing
terminal.
