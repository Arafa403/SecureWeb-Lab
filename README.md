# SecureWeb-Lab

A local web application security monitoring lab built with Node.js, Express, and SQLite.

## Overview

SecureWeb-Lab demonstrates core web security monitoring concepts through a dashboard for security event logging, failed login tracking, WAF detections, and SIEM-style incident monitoring.

## Features

- Security event logging with SQLite
- Failed login attempt tracking
- WAF detection events for suspicious input
- Security event dashboard with filtering and search
- SIEM-style event summaries and incident correlation
- Automatic dashboard refresh

## Technology Stack

- Node.js
- Express.js
- SQLite
- JavaScript
- HTML and CSS

## Getting Started

1. Install Node.js.
2. Clone this repository.
3. Run `npm install`.
4. Configure the required environment variables using the example configuration, if provided.
5. Start the application using the project's configured start command.
6. Open the local URL shown by the application.

## Security Notes

This project is intended for local learning and authorized testing.

The current WAF detection mode records suspicious activity. Do not assume that every detected request is automatically blocked. Any firewall integration or IP-blocking capability should be verified separately.

## Current Status

Educational project under active development.

## Author

Arafa Mohamed
