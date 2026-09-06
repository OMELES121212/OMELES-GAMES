const { app, BrowserWindow } = require("electron");
const path = require("path");

function createWindow() {
const win = new BrowserWindow({
width: 1100,
height: 750,
minWidth: 900,
minHeight: 600,
backgroundColor: "#05050a",


    webPreferences: {
        contextIsolation: true,
        nodeIntegration: false
    },

    autoHideMenuBar: true
});

win.loadFile(path.join(__dirname, "public", "index.html"));


}

app.whenReady().then(() => {
createWindow();

```
app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
```

});

app.on("window-all-closed", () => {
if (process.platform !== "darwin") {
app.quit();
}
});
