const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    icon: path.join(__dirname, 'public/icon-512.png'),
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    }
  });

  // Hide the default menu bar (File, Edit, View, etc.) for a clean app look
  win.setMenuBarVisibility(false);

  // Load your live Vercel app!
  win.loadURL('https://ai-code-reviewer-kappa-navy.vercel.app');
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});