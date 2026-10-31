-- Sample dump for local testing (mixed dialects are fine; detection picks the
-- strongest signal).
CREATE TABLE "users" (
    "id" integer NOT NULL,
    "email" character varying(255) NOT NULL,
    "first_name" text,
    "last_name" text,
    "phone" text,
    "ssn" text,
    "password_hash" text,
    "created_at" timestamp
);

INSERT INTO "users" ("id", "email", "first_name", "last_name", "phone", "ssn", "password_hash", "created_at") VALUES
    (1, 'jane.doe@acme.com', 'Jane', 'Doe', '+1-415-555-0199', '123-45-6789', '$2b$12$abcdef', '2024-01-02 03:04:05'),
    (2, 'bob@example.org', 'Bob', 'Smith', '555.867.5309', '987-65-4321', '$2b$12$ghijkl', '2024-02-03 04:05:06');

CREATE TABLE "orders" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ship_address TEXT,
    total NUMERIC
);

INSERT INTO "orders" VALUES (1, 1, '742 Evergreen Terrace', 19.99);
