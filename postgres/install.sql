------------------------------------------------
-- Database installation script.
-- 
-- Copyright Gleich-IT GmbH 2022
------------------------------------------------


------------------------ EXTENSIONS ------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";


------------------------ TABLES ------------------------
CREATE TABLE IF NOT EXISTS "information" (
    "id" SMALLINT GENERATED ALWAYS AS IDENTITY,
    "version" VARCHAR(20) NOT NULL UNIQUE,
    "changelog" TEXT,
    "date_add" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "jitsi_user" (
    "id" INT GENERATED ALWAYS AS IDENTITY,
    "uuid" UUID NOT NULL DEFAULT uuid_generate_v4(),
    "first_name" TEXT NOT NULL,
    "last_name" TEXT NOT NULL,
    "email" TEXT NOT NULL UNIQUE,
    "password_hash" TEXT NOT NULL,
    "is_admin" BOOLEAN NOT NULL DEFAULT FALSE,
    "date_add" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE FUNCTION "jitsi_encrypt" (IN in_text TEXT)
RETURNS TEXT
RETURNS NULL ON NULL INPUT
LANGUAGE plpgsql
AS $$
    BEGIN
        RETURN encrypt(in_text::bytea, '${ENV_PASSWORD}', 'bf');
    END;
$$;


------------------------ FUNCTIONS ------------------------
CREATE FUNCTION "jitsi_decrypt" (IN in_text TEXT)
RETURNS TEXT
RETURNS NULL ON NULL INPUT
LANGUAGE plpgsql
AS $$
    BEGIN
        RETURN convert_from(decrypt(in_text::bytea, '${ENV_PASSWORD}', 'bf'), 'UTF8');
    END;
$$;

CREATE FUNCTION "jitsi_new_password" (IN in_password TEXT)
RETURNS TEXT
RETURNS NULL ON NULL INPUT
LANGUAGE plpgsql
AS $$
    BEGIN
        RETURN crypt(in_password, gen_salt('md5'));
    END;
$$;

CREATE FUNCTION "jitsi_password" (IN in_password TEXT, IN in_hash TEXT)
RETURNS TEXT
RETURNS NULL ON NULL INPUT
LANGUAGE plpgsql
AS $$
    BEGIN
        RETURN crypt(in_password, in_hash);
    END;
$$;


------------------------ PROCEDURES ------------------------
CREATE PROCEDURE "proc_jitsi_first_install" ()
LANGUAGE plpgsql
AS $$
    BEGIN
        INSERT INTO information (version, changelog)
        VALUES ('1.0.0', '- Installation von Jitsi')
        ON CONFLICT DO NOTHING;

        INSERT INTO jitsi_user (first_name, last_name, email, password_hash, is_admin) 
        SELECT jitsi_encrypt('Administrator'), jitsi_encrypt('Administrator'), jitsi_encrypt('Administrator'), jitsi_new_password('Start01!'), TRUE
        FROM jitsi_user
        HAVING COUNT(id) = 0;

        COMMIT;
    END;
$$;


------------------------ EXECUTION ------------------------
CALL proc_jitsi_first_install();
DROP PROCEDURE proc_jitsi_first_install;
