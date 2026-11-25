package ui

import "embed"

// Assets holds the embedded static files for the minimalist web UI.
//
//go:embed index.html styles.css app.js
var Assets embed.FS
