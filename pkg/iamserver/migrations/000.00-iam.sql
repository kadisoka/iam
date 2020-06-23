--
\set ON_ERROR_STOP true

BEGIN;
------

CREATE TABLE users (
    id                   bigint PRIMARY KEY,
    creation_time        timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id     bigint NOT NULL,
    creation_terminal_id bigint NOT NULL,
    deletion_time        timestamp with time zone,
    deletion_user_id     bigint,
    deletion_terminal_id bigint,
    deletion_notes       jsonb,
    CHECK (id > 0)
);

CREATE TABLE user_phone_numbers (
    user_id               bigint NOT NULL,
    country_code          integer NOT NULL,
    national_number       bigint NOT NULL, -- libphonenumber says uint64
    raw_input             text NOT NULL,
    is_primary            boolean NOT NULL DEFAULT false, 
    creation_time         timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id      bigint NOT NULL,
    creation_terminal_id  bigint NOT NULL,
    deletion_time         timestamp with time zone,
    deletion_user_id      bigint,
    deletion_terminal_id  bigint,
    verification_id       bigint NOT NULL DEFAULT 0,
    verification_time     timestamp with time zone
);
-- Each user can only have one reference to the same phone number
CREATE UNIQUE INDEX user_phone_numbers_pidx
    ON user_phone_numbers (user_id, country_code, national_number)
    WHERE deletion_time IS NULL;
-- Each user has only one primary
CREATE UNIQUE INDEX user_phone_numbers_user_id_uidx
    ON user_phone_numbers (user_id)
    WHERE deletion_time IS NULL AND verification_time IS NOT NULL AND is_primary IS TRUE;
-- One instance of active primary for each phone number
CREATE UNIQUE INDEX user_phone_numbers_country_code_national_number_uidx
    ON user_phone_numbers (country_code, national_number)
    WHERE deletion_time IS NULL AND verification_time IS NOT NULL AND is_primary IS TRUE;
CREATE INDEX user_phone_numbers_user_id_verified_idx
    ON user_phone_numbers (user_id)
    WHERE deletion_time IS NULL AND verification_time IS NOT NULL;
CREATE INDEX user_phone_numbers_country_code_national_number_verified_idx
    ON user_phone_numbers (country_code, national_number)
    WHERE deletion_time IS NULL AND verification_time IS NOT NULL;

CREATE TABLE terminals (
    id                   bigint PRIMARY KEY,
    client_id            integer NOT NULL,
    user_id              bigint,
    secret               text NOT NULL,
    display_name         text,
    accept_language      text NOT NULL DEFAULT '',
    platform_type        text NOT NULL DEFAULT '', --TODO: remove this

    creation_time        timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id     bigint,
    creation_terminal_id bigint,
    creation_ip_address  text,
    creation_user_agent  text,

    verification_type    text NOT NULL,
    verification_id      bigint NOT NULL,
    verification_time    timestamp with time zone,

    CHECK (id > 0 AND client_id > 0)
);
CREATE INDEX ON terminals (user_id)
    WHERE verification_time IS NOT NULL;

CREATE TABLE terminal_authorizations (
    terminal_id          bigint NOT NULL,
    authorization_id     bigint NOT NULL,
    creation_time        timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id     bigint,
    creation_terminal_id bigint,
    deletion_time        timestamp with time zone,
    deletion_user_id     bigint,
    deletion_terminal_id bigint,
    PRIMARY KEY (terminal_id, authorization_id),
    CHECK (terminal_id > 0 AND authorization_id > 0)
);

CREATE TABLE user_terminal_fcm_registration_tokens (
    user_id              bigint NOT NULL,
    terminal_id          bigint NOT NULL,
    token                text NOT NULL,
    creation_time        timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id     bigint NOT NULL,
    creation_terminal_id bigint NOT NULL,
    deletion_time        timestamp with time zone,
    deletion_user_id     bigint,
    deletion_terminal_id bigint
);
CREATE UNIQUE INDEX user_terminal_fcm_registration_tokens_pidx
    ON user_terminal_fcm_registration_tokens (user_id, terminal_id)
    WHERE deletion_time IS NULL;

CREATE TABLE phone_number_verifications (
    id                       bigserial PRIMARY KEY,
    country_code             integer NOT NULL,
    national_number          bigint NOT NULL,
    code                     text NOT NULL,
    code_expiry              timestamp with time zone,
    attempts_remaining       smallint NOT NULL DEFAULT 3,
    creation_time            timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id         bigint,
    creation_terminal_id     bigint,
    confirmation_time        timestamp with time zone,
    confirmation_user_id     bigint,
    confirmation_terminal_id bigint
);

CREATE TABLE user_contact_phone_numbers (
    user_id                  bigint NOT NULL,
    contact_country_code     integer NOT NULL,
    contact_national_number  bigint NOT NULL,
    creation_time            timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id         bigint NOT NULL,
    creation_terminal_id     bigint NOT NULL,
    PRIMARY KEY (user_id, contact_country_code, contact_national_number)
);

-- user profile
CREATE TABLE user_display_names (
    user_id               bigint NOT NULL,
    display_name          text NOT NULL,
    creation_time         timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id      bigint NOT NULL,
    creation_terminal_id  bigint NOT NULL,
    deletion_time         timestamp with time zone,
    deletion_user_id      bigint,
    deletion_terminal_id  bigint
);
CREATE UNIQUE INDEX user_display_names_pidx ON user_display_names (user_id)
    WHERE deletion_time IS NULL;

CREATE TABLE user_profile_image_urls (
    user_id               bigint NOT NULL,
    profile_image_url     text NOT NULL,
    creation_time         timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id      bigint NOT NULL,
    creation_terminal_id  bigint NOT NULL,
    deletion_time         timestamp with time zone,
    deletion_user_id      bigint,
    deletion_terminal_id  bigint
);
CREATE UNIQUE INDEX user_profile_image_urls_pidx ON user_profile_image_urls (user_id)
    WHERE deletion_time IS NULL;

-- user email
CREATE TABLE user_email_addresses (
    user_id               bigint NOT NULL,
    local_part            text NOT NULL,
    domain_part           text NOT NULL,
    raw_input             text NOT NULL,
    is_primary            boolean NOT NULL DEFAULT false,
    creation_time         timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id      bigint NOT NULL,
    creation_terminal_id  bigint NOT NULL,
    deletion_time         timestamp with time zone,
    deletion_user_id      bigint,
    deletion_terminal_id  bigint,
    verification_id       bigint NOT NULL DEFAULT 0,
    verification_time     timestamp with time zone
);
-- Each user can only have one reference to the same email address
CREATE UNIQUE INDEX user_email_addresses_pidx
    ON user_email_addresses (user_id, local_part, domain_part)
    WHERE deletion_time IS NULL;
-- To ensure that each user has only one primary
CREATE UNIQUE INDEX user_email_addresses_user_id_uidx
    ON user_email_addresses (user_id)
    WHERE deletion_time IS NULL AND verification_time IS NOT NULL AND is_primary IS TRUE;
-- To ensure that a email address is active as primary
CREATE UNIQUE INDEX user_email_addresses_local_part_domain_part_uidx
    ON user_email_addresses (local_part, domain_part)
    WHERE deletion_time IS NULL AND verification_time IS NOT NULL AND is_primary IS TRUE;
CREATE INDEX user_email_addresses_user_id_verified_idx
    ON user_email_addresses (user_id)
    WHERE deletion_time IS NULL AND verification_time IS NOT NULL;
CREATE INDEX user_email_addresses_local_part_domain_part_verified_idx
    ON user_email_addresses (local_part, domain_part)
    WHERE deletion_time IS NULL AND verification_time IS NOT NULL;

CREATE TABLE email_address_verifications (
    id                       bigserial PRIMARY KEY,
    local_part               text NOT NULL,
    domain_part              text NOT NULL,
    code                     text NOT NULL,
    code_expiry              timestamp with time zone,
    attempts_remaining       smallint NOT NULL DEFAULT 3,
    creation_time            timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id         bigint,
    creation_terminal_id     bigint,
    confirmation_time        timestamp with time zone,
    confirmation_user_id     bigint,
    confirmation_terminal_id bigint
);

-- user password
--TODO: passwords for different purposes?
CREATE TABLE user_passwords (
    user_id               bigint NOT NULL,
    password              text NOT NULL,
    creation_time         timestamp with time zone NOT NULL DEFAULT now(),
    creation_user_id      bigint NOT NULL,
    creation_terminal_id  bigint NOT NULL,
    deletion_time         timestamp with time zone,
    deletion_user_id      bigint,
    deletion_terminal_id  bigint
);
CREATE UNIQUE INDEX ON user_passwords (user_id)
    WHERE deletion_time IS NULL;

----
END;
