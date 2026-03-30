# User Acceptance Testing (UAT) Checklist

## Environment readiness

- [ ] Application starts successfully.
- [ ] Database connectivity is healthy.
- [ ] Required environment variables are configured.

## Authentication & authorization

- [ ] Login works with valid credentials.
- [ ] Invalid login shows safe generic error.
- [ ] Role-based page access is enforced.

## Dashboard pages

- [ ] Asset Inventory loads and table paginates.
- [ ] Asset Discovery graph and table load.
- [ ] CBOM dashboard renders KPIs and rows.
- [ ] PQC posture dashboard renders KPIs and rows.
- [ ] Cyber rating dashboard renders KPIs and rows.
- [ ] Reporting dashboard loads schedules section.

## API-first endpoints

- [ ] `/api/assets` returns standard envelope.
- [ ] `/api/discovery` returns standard envelope.
- [ ] `/api/cbom` returns standard envelope.
- [ ] `/api/pqc-posture` returns standard envelope.
- [ ] `/api/cyber-rating` returns standard envelope.
- [ ] `/api/reports` returns standard envelope.

## Operational workflows

- [ ] Scan submission works for valid target.
- [ ] PDF report generation returns downloadable PDF.
- [ ] Report scheduling and listing work.
- [ ] Asset delete and restore flows work.

## Security checks

- [ ] Response includes security headers.
- [ ] API key protected endpoints reject missing/invalid keys in non-test mode.
- [ ] Password policy enforces complexity.

## Sign-off

- [ ] Product Owner sign-off
- [ ] Security sign-off
- [ ] QA sign-off
