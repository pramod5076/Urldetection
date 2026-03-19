# Deployment Guide: PhishGuard AI 🌐

Follow these steps to deploy your PhishGuard AI application and Chrome Extension back-end to the cloud using **Render.com**.

## 🛡️ Important: Selenium in Production
PhishGuard AI uses Selenium to capture screenshots. Standard cloud hosts don't have Chrome installed. Render is recommended because it allows us to use **Docker** or **Buildpacks** to install Chrome.

---

## 🚀 Step 1: Prepare your Code
I have already added the following files to your project:
- **`Procfile`**: Tells the server how to start the app.
- **`requirements.txt`**: Now includes `gunicorn` for a stable production server.

---

## 🌍 Step 2: Deploy to Render.com

1. **Sign up**: Go to [Render.com](https://render.com/) and connect your GitHub account.
2. **New Web Service**:
   - Click **New +** > **Web Service**.
   - Select your `Urldetection` repository.
3. **Configure Settings**:
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
4. **Environment Variables**:
   In the **Environment** tab, add your VirusTotal key:
   - Key: `VT_API_KEY`
   - Value: `(Your API Key here)`
5. **Headless Chrome (CRITICAL)**:
   In the **Build Filter** or **Settings**, add these Buildpacks (if not using Docker):
   - `https://github.com/heroku/heroku-buildpack-google-chrome`
   - `https://github.com/heroku/heroku-buildpack-chromedriver`

---

## 🧩 Step 3: Update your Chrome Extension

Once your site is live (e.g., `https://your-app-name.onrender.com`):
1. Open `extension/background.js` and `extension/popup.js`.
2. Change the `API_URL` from `http://127.0.0.1:5000` to your **NEW Live URL**.
3. Reload your extension in `chrome://extensions/`.

---

## ✨ Summary
Your app is now ready for the world! Whenever you push code to GitHub, Render will automatically rebuild and update your live site. 🚀
