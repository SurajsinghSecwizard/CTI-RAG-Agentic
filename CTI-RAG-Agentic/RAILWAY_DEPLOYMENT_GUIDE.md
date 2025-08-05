# Railway Deployment Guide

## Step 1: Prepare Your Repository
Your code is already ready! The following files are now included:
- `requirements.txt` - All dependencies
- `runtime.txt` - Python version
- `Procfile` - How to start the app
- All your agentic system files

## Step 2: Deploy to Railway

### Option A: Deploy via Railway Dashboard
1. Go to [railway.app](https://railway.app)
2. Sign up/Login with GitHub
3. Click "New Project"
4. Select "Deploy from GitHub repo"
5. Choose your repository: `CTI-RAG-Agentic`
6. Railway will automatically detect it's a Python app
7. Click "Deploy"

### Option B: Deploy via Railway CLI
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Initialize project
railway init

# Deploy
railway up
```

## Step 3: Set Environment Variables
After deployment, set these environment variables in Railway dashboard:

### Required Variables:
```
AZURE_SEARCH_ENDPOINT=your_azure_search_endpoint
AZURE_SEARCH_KEY=your_azure_search_key
AZURE_SEARCH_INDEX_NAME=your_index_name
OPENAI_API_KEY=your_openai_api_key
OPENAI_API_BASE=https://your-openai-resource.openai.azure.com/
OPENAI_API_VERSION=2024-02-15-preview
```

### Optional Variables:
```
REDIS_URL=your_redis_url (if using Redis)
AZURE_STORAGE_CONNECTION_STRING=your_storage_connection
```

## Step 4: Access Your App
- Railway will provide a URL like: `https://your-app-name.railway.app`
- Your app will be live in 5-10 minutes!

## Troubleshooting
- Check Railway logs if deployment fails
- Ensure all environment variables are set
- The app will automatically restart on code changes

## Cost
- Free tier: $5 credit/month
- Pay-as-you-use after that
- Estimated cost: $0-20/month for development 