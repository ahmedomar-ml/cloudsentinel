# Frontend setup (Angular dashboard)

The dashboard files are in `frontend-src/`. They were written for a standard new Angular project (v17 or newer, standalone components). They have NOT been built or run yet, so if anything fails, send the error message.

## 1. Create the Angular project

From the `cloudsentinel` folder (not inside `backend`):

```bash
ng new frontend --routing=false --style=css
```

Answer the prompts with the defaults. For SSR/prerendering choose **No**.

## 2. Copy the dashboard files into it

- `frontend-src/main.ts`                    -> `frontend/src/main.ts` (replace the existing file)
- `frontend-src/app/scan.service.ts`        -> `frontend/src/app/scan.service.ts`
- `frontend-src/app/dashboard.component.ts` -> `frontend/src/app/dashboard.component.ts`

The generated `app.ts` / `app.component.ts` files stay where they are but are no longer used.

## 3. Run both servers (two terminals)

Terminal 1 (backend):

```bash
cd backend
venv\Scripts\activate
uvicorn main:app --reload
```

Terminal 2 (frontend):

```bash
cd frontend
ng serve
```

Open http://localhost:4200 and click a sample environment.

## If something goes wrong

- "Cannot reach the API" message on the page: the backend is not running, or is not on port 8000.
- Build error: copy the full error text and send it.
