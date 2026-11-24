# InstaName Finder — Railway deployment

## Deploy to Railway (no `.env` file needed)

1. Push the contents of this project folder to a GitHub repository.
2. In Railway, create a project and choose **Deploy from GitHub Repo**.
3. Select the repository. Railway detects `package.json` and runs `npm start`.
4. Open your Railway service → **Variables**.
5. Add this variable:

   `APIFY_TOKEN` = `your_actual_apify_token`

6. Redeploy if Railway does not automatically redeploy after adding the variable.
7. Open the public Railway domain generated for the service.

That's it. The backend reads `process.env.APIFY_TOKEN`, which is exactly where Railway injects service variables. The browser never receives the token.

## Local testing (optional)

Requires Node.js 18+. You can set `APIFY_TOKEN` in your shell, then run `npm start`.
A local `.env` file is also supported for convenience, but it is not required on Railway.

## Files
- `public/index.html`: frontend.
- `server.js`: backend API proxy. Serves the frontend and calls Apify without exposing your token.
- `package.json`: Railway start script (`npm start`).
- `railway.json`: Railway deployment configuration.

## Important API note
The integration calls the third-party Apify Actor `instagram-data-api/instagram-username-checker`. It is not an official Instagram API. Review the Actor's current input schema, pricing and terms in Apify before use. The backend currently sends `{ "usernames": [...] }`; if the Actor's current input schema uses a different field, update that request body in `server.js`.

Results are third-party estimates, not a guarantee Instagram will accept a username. Missing or unclear results should remain unverified, not be treated as available.
