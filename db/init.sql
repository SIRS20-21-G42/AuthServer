--
-- Current Database: `authdb`
--

DROP DATABASE IF EXISTS `authdb`;
CREATE DATABASE `authdb`;

CREATE USER IF NOT EXISTS 'auth'@'%' IDENTIFIED BY 'authpass';
GRANT all privileges ON authdb.* TO 'auth'@'%';
FLUSH PRIVILEGES
