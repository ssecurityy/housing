# 📋 Deployment Guide - Cyber Month 2025

## 🚀 GitHub Setup (Step by Step)

### 1. Initialize Git Repository
```bash
cd /Users/rahulmalhotra/Documents/Testing_Housing/Cyber_Month
git init
```

### 2. Add All Files
```bash
git add .
```

### 3. Create Initial Commit
```bash
git commit -m "Initial commit: Cyber Month 2025 - Housing.com Security Awareness Platform"
```

### 4. Create GitHub Repository
1. Go to [GitHub](https://github.com)
2. Click the **+** icon → **New repository**
3. Repository name: `cyber-month-2025`
4. Description: "Interactive cybersecurity awareness platform for Housing.com & REA India"
5. Set to **Public** (or Private if preferred)
6. **DON'T** initialize with README (we already have one)
7. Click **Create repository**

### 5. Connect Local to GitHub
```bash
# Replace 'yourusername' with your GitHub username
git remote add origin https://github.com/yourusername/cyber-month-2025.git
git branch -M main
git push -u origin main
```

## 🌐 Netlify Deployment

### Method 1: GitHub Integration (Recommended)

1. Go to [Netlify](https://app.netlify.com)
2. Click **Add new site** → **Import an existing project**
3. Choose **GitHub**
4. Authorize Netlify to access your GitHub
5. Select the `cyber-month-2025` repository
6. Build settings:
   - **Base directory**: Leave empty
   - **Build command**: Leave empty (static site)
   - **Publish directory**: `.` (root)
7. Click **Deploy site**

### Method 2: Drag & Drop

1. Go to [Netlify Drop](https://app.netlify.com/drop)
2. Open your project folder in Finder/Explorer
3. Drag the entire `Cyber_Month` folder to the browser
4. Wait for upload to complete
5. Your site is live!

### Method 3: Netlify CLI

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Login to Netlify
netlify login

# Deploy
netlify deploy --prod --dir .
```

## 🔧 Post-Deployment Setup

### 1. Custom Domain (Optional)
1. In Netlify dashboard → **Domain settings**
2. Add custom domain
3. Follow DNS configuration instructions

### 2. Enable Analytics (Optional)
1. In Netlify dashboard → **Analytics**
2. Enable analytics for visitor insights

### 3. Form Notifications (If needed)
1. In Netlify dashboard → **Forms**
2. Set up email notifications

## 📝 Environment Variables

No environment variables needed for this static site!

## 🔄 Continuous Deployment

With GitHub integration, every push to `main` branch automatically deploys:

```bash
# Make changes
git add .
git commit -m "Update: description of changes"
git push
```

## 🛡️ Security Headers

Already configured in `netlify.toml`:
- X-Frame-Options
- Content Security Policy
- XSS Protection
- And more!

## 📊 Performance Optimization

The site is already optimized with:
- Minified external libraries
- Efficient animations
- Lazy loading ready
- Proper caching headers

## 🚨 Troubleshooting

### Build Fails
- Check console for errors
- Ensure all files are committed
- Verify file paths are correct (case-sensitive)

### Images Not Loading
- Check image paths in code
- Ensure Images folder is included
- Verify file extensions match

### Animations Not Working
- Clear browser cache
- Check browser console for errors
- Ensure JavaScript is enabled

## 📱 Testing Checklist

Before going live, test:
- [ ] Desktop view (Chrome, Firefox, Safari)
- [ ] Mobile view (iOS, Android)
- [ ] TV mode functionality
- [ ] Tips & Tricks navigation
- [ ] Team slider animation
- [ ] Incident alert displays
- [ ] All 23 demo cards load
- [ ] Responsive design breakpoints

## 🎉 Success!

Your site should now be live at:
- Netlify: `https://[your-site-name].netlify.app`
- Custom domain: `https://your-domain.com` (if configured)

## 📞 Support

For deployment issues:
- GitHub: Check [GitHub Docs](https://docs.github.com)
- Netlify: Visit [Netlify Support](https://docs.netlify.com)
- Project specific: cyberprotect@housing.com

---

**Happy Deploying! 🚀**
