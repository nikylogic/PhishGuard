# Who can do what (HTTP status returned)

| Request | Not logged in | Analyst | Admin |
|---|---|---|---|
| `GET /api/scans` | 401 log in | 200 allowed | 200 allowed |
| `GET /api/stats` | 401 log in | 200 allowed | 200 allowed |
| `GET /api/lists` | 401 log in | 200 allowed | 200 allowed |
| `POST /api/lists` | 401 log in | 201 allowed | 201 allowed |
| `POST /api/guard` | 401 log in | 200 allowed | 200 allowed |
| `POST /api/scan` | 401 log in | 201 allowed | 201 allowed |
| `GET /api/settings` | 401 log in | 403 refused | 200 allowed |
| `POST /api/settings` | 401 log in | 403 refused | 200 allowed |
| `GET /api/users` | 401 log in | 403 refused | 200 allowed |
| `POST /api/users` | 401 log in | 403 refused | 201 allowed |
| `GET /api/audit` | 401 log in | 403 refused | 200 allowed |
