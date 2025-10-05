# Tenable Audit Viewer

A Python GUI application for viewing, editing, and exporting Tenable .audit files in a user-friendly table format.

## What It Does

- **Parses .audit files** - Reads Tenable .audit files
- **Table view** - Displays audit checks in an editable spreadsheet-like interface
- **Edit capabilities** - Click any cell to edit values directly
- **Export options** - Save changes in .audit format or export to CSV


- Should work on Windows, macOS, and Linux (Only tested on Windows though)

## Requirements

### Python Version
- **Python 3.6 or higher**

### Required Libraries
All libraries are part of Python's standard library - **no additional installation should be required, but if so, see list below**:
- `tkinter` (GUI framework)
- `csv` (CSV export)
- `os` (file operations)
- `re` (text parsing)
- `xml.etree.ElementTree` (XML parsing)

## Installation

1. **Download the script**: Save `audit_viewer.py` to your computer
2. **Ensure Python is installed**: Run `python --version` to check
3. **No additional packages needed** - uses only Python standard library

## How to Use

### 1. Start the Application
```bash
python audit_viewer.py
```

### 2. Import an Audit File
- Download audit files from https://www.tenable.com/downloads/download-all-compliance-audit-files
- Click **"Import .audit File"**
- Select your .audit file
- The table will populate with all audit checks

### 3. Edit Values
- **Click any cell** to edit its value
- Press **Enter** to save changes
- Press **Escape** to cancel editing

### 4. Export Changes
- **Export to CSV**: Save data as a spreadsheet
- **Export .audit**: Save changes back to .audit format
- Progress dialog shows export status

## File Formats Supported

- **Input**: `.audit` files (Tenable audit file format)
- **Output**: `.audit` files (preserves original structure) or `.csv` files
