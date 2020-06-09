This folder contains secrets for the IAM services. Do not commit anything
contained in here.

IAM service will attempt to load these secrets:

- `clients.csv` -- as we haven't implemented client management, we use this
  file to store registered clients. As the file contains clients' secret,
  it needs to be placed here. Create yours by copying `clients.csv.example`
  as `clients.csv` and start adding rows.
- `jwt.key` -- a private key for use to sign JWT tokens. Currently it's
  limited to RSA. Use the command `openssl genrsa -out jwt.key 2048` to
  generate yours.
- `config.env` -- configuration for the service. For local execution, it's
  referenced by `docker-compose.yaml`.
