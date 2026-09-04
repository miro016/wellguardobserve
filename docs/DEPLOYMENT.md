# Deployment

## Easypanel or another Docker platform

1. Create an application from the GitHub repository and select the root `Dockerfile`.
2. Expose container port `8080` through HTTPS.
3. Mount a persistent volume at `/data`.
4. Configure all required environment variables from `.env.example`. Use a distinct random password for `POCKETBASE_WORKER_PASSWORD`; do not reuse the PocketBase superuser password.
5. Set `PUBLIC_ORIGIN` to the final HTTPS origin.
6. Set `OLLAMA_BASE_URL` to the private service URL of the Ollama instance.
7. Deploy and wait for `/healthz` (web liveness) and `/readyz` (PocketBase readiness) to report `200`.
8. Set `WELLGUARD_ADMIN_EMAIL` and `WELLGUARD_ADMIN_PASSWORD` to seed the first invited administrator and authorized acceptance target, or open a terminal and create an invited user with `scripts/create-user.ts`.

The deployment automatically applies PocketBase migrations, upserts the startup superuser, and provisions a separate least-privilege observer identity in the `workers` collection. Superuser credentials are removed from the observer process environment and never enter the browser bundle.

## Persistence and backups

The `/data` volume contains PocketBase records and must survive redeployments. Use PocketBase backups or snapshot the volume regularly. Test restoration before depending on historical observations.

## Scaling boundary

The all-in-one image is deliberate for the private MVP. Before horizontal scaling, move PocketBase, the web server, and observer workers into separate services and introduce durable queue leases so two workers cannot claim the same request.
