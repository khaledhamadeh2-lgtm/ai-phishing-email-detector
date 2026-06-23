# Security policy

PhishGuard is an educational, defensive analyzer—not an email gateway or a substitute for professional controls.
Please report vulnerabilities privately through GitHub's security-advisory feature rather than a public issue.

The service processes email content in memory, never follows links, and ignores attachments. Deployments should add
TLS, authentication, rate limiting, a strict retention policy, and monitoring before accepting sensitive email.
