-- A.P.E. Database Initialization Script
-- Run this on your PostgreSQL instance before starting the server

-- Create database and user
CREATE DATABASE ape_secrets;
CREATE USER ape_user WITH PASSWORD 'ape_password';

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE ape_secrets TO ape_user;

-- Connect to the database
\c ape_secrets;

-- Grant schema permissions
GRANT ALL ON SCHEMA public TO ape_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ape_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ape_user;

-- Enable UUID extension (the application will also try to create this)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
