#!/usr/bin/env python3
"""
Tenable Audit File Viewer
A tool to parse Tenable .audit files and display them in a human-readable format
with import/edit/export functionality.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import os
from typing import List, Dict, Any
import re


# Main parser class that handles reading and writing .audit files
class AuditParser:
    def __init__(self):
        self.parsed_data = []
        self.check_counter = 0
        self.all_fields = set()
        self.original_file_content = ""
        self.original_parsed_data = []
        
    # Loads and parses .audit file
    def parse_audit_file(self, file_path: str) -> List[Dict[str, Any]]:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            
            self.original_file_content = content
            self.parsed_data = []
            self.check_counter = 0
            self.all_fields = set()
            
            # Parse custom_item blocks
            custom_item_pattern = r'<custom_item>(.*?)</custom_item>'
            custom_items = re.findall(custom_item_pattern, content, re.DOTALL)
            
            for item_content in custom_items:
                self.check_counter += 1
                check_data = self._extract_custom_item_data(item_content)
                check_data['check_number'] = str(self.check_counter)
                check_data['level'] = 0
                self.parsed_data.append(check_data)
            
            # Parse if blocks with nested items
            if_pattern = r'<if\s+condition="([^"]*)"[^>]*>(.*?)</if>'
            if_blocks = re.findall(if_pattern, content, re.DOTALL)
            
            for condition, if_content in if_blocks:
                nested_items = re.findall(custom_item_pattern, if_content, re.DOTALL)
                for i, item_content in enumerate(nested_items):
                    self.check_counter += 1
                    check_data = self._extract_custom_item_data(item_content)
                    check_data['check_number'] = f"{self.check_counter}{chr(ord('A') + i)}"
                    check_data['level'] = 1
                    check_data['condition'] = condition
                    self.parsed_data.append(check_data)
            
            self.original_parsed_data = [check.copy() for check in self.parsed_data]
            return self.parsed_data
            
        except Exception as e:
            raise Exception(f"Error reading file: {e}")
    
    def _extract_custom_item_data(self, item_content: str) -> Dict[str, Any]:
        check_data = {
            'check_number': '',
            'level': 0,
            'raw_content': item_content
        }
        
        lines = item_content.split('\n')
        current_field = None
        current_value = []
        in_quoted_value = False
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            field_match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)$', line)
            if field_match:
                if current_field and current_value:
                    field_value = '\n'.join(current_value).strip()
                    check_data[current_field] = field_value
                    self.all_fields.add(current_field)
                
                field_name = field_match.group(1).strip()
                field_value = field_match.group(2).strip()
                
                if field_value.startswith('"'):
                    if field_value.endswith('"') and not field_value.endswith('\\"'):
                        check_data[field_name] = field_value[1:-1]
                        self.all_fields.add(field_name)
                        current_field = None
                        current_value = []
                        in_quoted_value = False
                    else:
                        current_field = field_name
                        current_value = [field_value[1:]]
                        in_quoted_value = True
                else:
                    current_field = field_name
                    current_value = [field_value]
                    in_quoted_value = False
            else:
                if current_field:
                    if in_quoted_value:
                        if line.endswith('"') and not line.endswith('\\"'):
                            current_value.append(line[:-1])
                            check_data[current_field] = '\n'.join(current_value).strip()
                            self.all_fields.add(current_field)
                            current_field = None
                            current_value = []
                            in_quoted_value = False
                        else:
                            current_value.append(line)
                    else:
                        current_value.append(line)
        
        if current_field and current_value:
            field_value = '\n'.join(current_value).strip()
            check_data[current_field] = field_value
            self.all_fields.add(current_field)
        
        if check_data.get('name'):
            check_data['title'] = check_data['name']
        elif check_data.get('description'):
            check_data['title'] = check_data['description']
        
        if check_data.get('description'):
            check_data['description'] = re.sub(r'[ \t]+', ' ', check_data['description']).strip()
        
        return check_data
    
    def _build_custom_item_content(self, check_data: Dict[str, Any]) -> str:
        content_lines = []
        exclude_fields = {'check_number', 'title', 'raw_content', 'attributes', 'level', 'full_values'}
        
        #Order of fields to be displayed in the .audit file
        field_order = ['system', 'type', 'description', 'info', 'reference', 'see_also', 
                      'cmd', 'expect', 'not_expect', 'file', 'regex', 'search_locations',
                      'owner', 'group', 'mask', 'severity', 'show_output', 'required',
                      'min_occurrences', 'file_required', 'string_required']
        
        for field in field_order:
            if field in check_data and check_data[field] and field not in exclude_fields:
                if 'full_values' in check_data and field in check_data['full_values']:
                    value = check_data['full_values'][field]
                else:
                    value = check_data[field]
                
                if isinstance(value, str):
                    content_lines.append(f"      {field:<15} : \"{value}\"")
                else:
                    content_lines.append(f"      {field:<15} : {value}")
        
        for field, value in check_data.items():
            if field not in exclude_fields and field not in field_order and value:
                if 'full_values' in check_data and field in check_data['full_values']:
                    value = check_data['full_values'][field]
                else:
                    value = check_data[field]
                
                if isinstance(value, str):
                    content_lines.append(f"      {field:<15} : \"{value}\"")
                else:
                    content_lines.append(f"      {field:<15} : {value}")
        
        return '\n'.join(content_lines)
    
    # Processes audit export by updating custom_item blocks
    def process_audit_export(self, file_path: str, updated_data: List[Dict[str, Any]], progress_callback=None) -> None:
        if not self.original_file_content:
            raise Exception("No original file content available for export")
        
        if not self.original_parsed_data:
            raise Exception("No original parsed data available for comparison")
        
        content = self.original_file_content
        
        if '<custom_item>' in content:
            pattern = r'(<custom_item>.*?</custom_item>)'
            matches = re.findall(pattern, content, re.DOTALL)
            
            total_checks = len(updated_data)
            for i, check_data in enumerate(updated_data):
                if progress_callback:
                    progress_callback(i + 1, total_checks, f"Processing check {check_data['check_number']}...")
                
                # Find the original data for this check to match against
                original_data = None
                for orig_check in self.original_parsed_data:
                    if orig_check['check_number'] == check_data['check_number']:
                        original_data = orig_check
                        break
                
                #There may be a better way to handle matching against the correct item block.
                if original_data:
                    # Find the best matching custom_item block
                    best_match = None
                    for match in matches:
                        # Simple matching: if the original description is in this match, it's likely the right one
                        if original_data.get('description') and original_data['description'] in match:
                            best_match = match
                            break
                        # Fallback: if description doesn't match, try other fields
                        elif original_data.get('cmd') and original_data['cmd'] in match:
                            best_match = match
                            break
                    
                    if best_match:
                        new_item_content = self._build_custom_item_content(check_data)
                        new_item = f'<custom_item>\n{new_item_content}\n    </custom_item>'
                        content = content.replace(best_match, new_item)
        
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
    
    def get_modified_checks(self, current_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        modified_checks = []
        
        original_by_check_number = {}
        for original_check in self.original_parsed_data:
            original_by_check_number[original_check['check_number']] = original_check
        
        for current_check in current_data:
            check_number = current_check['check_number']
            if check_number in original_by_check_number:
                original_check = original_by_check_number[check_number]
                
                has_changes = False
                exclude_fields = {'check_number', 'title', 'raw_content', 'attributes', 'level', 'full_values'}
                for field, current_value in current_check.items():
                    if field not in exclude_fields:
                        original_value = original_check.get(field, '')
                        if str(current_value) != str(original_value):
                            has_changes = True
                            break
                
                if has_changes:
                    modified_checks.append(current_check)
        
        return modified_checks
    


# Progress bar for export
class ProgressDialog:
    def __init__(self, parent, title="Processing", message="Please wait..."):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x150")
        self.dialog.resizable(False, False)
        
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.message_label = ttk.Label(main_frame, text=message, font=('Arial', 10))
        self.message_label.pack(pady=(0, 10))
        
        self.progress = ttk.Progressbar(main_frame, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(0, 10))
        
        self.status_label = ttk.Label(main_frame, text="", font=('Arial', 9))
        self.status_label.pack()
        
        self.dialog.update_idletasks()
        x = (parent.winfo_x() + (parent.winfo_width() // 2)) - (self.dialog.winfo_width() // 2)
        y = (parent.winfo_y() + (parent.winfo_height() // 2)) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")
    
    def update_progress(self, current, total, status=""):
        if total > 0:
            progress_value = (current / total) * 100
            self.progress['value'] = progress_value
        
        if status:
            self.status_label.config(text=status)
        
        self.dialog.update()
    
    def close(self):
        self.dialog.destroy()


# Main GUI table view
class AuditParserGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Tenable Audit File Viewer")
        self.root.geometry("1200x800")
        
        self.parser = AuditParser()
        self.current_data = []
        
        self.setup_ui()
    
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        title_label = ttk.Label(main_frame, text="Tenable Audit File Viewer", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.import_btn = ttk.Button(button_frame, text="Import .audit File", 
                                    command=self.import_audit_file)
        self.import_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_btn = ttk.Button(button_frame, text="Export to CSV", 
                                    command=self.export_to_csv, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_audit_btn = ttk.Button(button_frame, text="Export .audit", 
                                          command=self.export_to_audit, state=tk.DISABLED)
        self.export_audit_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_btn = ttk.Button(button_frame, text="Clear", 
                                   command=self.clear_data)
        self.clear_btn.pack(side=tk.LEFT)
        
        self.status_label = ttk.Label(main_frame, text="Ready to import .audit file")
        self.status_label.grid(row=1, column=2, sticky=tk.E, pady=(0, 10))
        
        self.setup_treeview(main_frame)
    
    def setup_treeview(self, parent):
        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        self.tree = ttk.Treeview(tree_frame, columns=('Check Number',), show='headings', height=20)
        
        v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        self.tree.bind('<Double-1>', self.show_details)
        self.tree.bind('<Button-1>', self.on_cell_click)
        self.tree.bind('<Key>', self.on_cell_edit)
        
        self.editing_item = None
        self.editing_column = None
        self.edit_entry = None
        self.modified_items = set()
    
    def update_treeview_columns(self, all_fields):
        priority_fields = ['Check Number', 'description', 'type', 'system', 'severity', 'required', 'file', 'cmd', 'expect']
        
        columns = []
        for field in priority_fields:
            if field in all_fields or field == 'Check Number':
                columns.append(field)
        
        for field in sorted(all_fields):
            if field not in columns and field not in ['check_number', 'title', 'raw_content', 'attributes', 'level']:
                columns.append(field)
        
        self.tree['columns'] = columns
        self.tree['show'] = 'headings'
        
        for col in columns:
            self.tree.heading(col, text=col.replace('_', ' ').title())
            
            if col == 'Check Number':
                self.tree.column(col, width=100, minwidth=80)
            elif col in ['description', 'info', 'solution']:
                self.tree.column(col, width=200, minwidth=150)
            elif col in ['type', 'system', 'severity', 'required']:
                self.tree.column(col, width=100, minwidth=80)
            elif col in ['file', 'cmd', 'expect']:
                self.tree.column(col, width=150, minwidth=100)
            else:
                self.tree.column(col, width=120, minwidth=80)
    
    # Loads .audit file and displays it in the table
    def import_audit_file(self):
        file_path = filedialog.askopenfilename(
            title="Select .audit file",
            filetypes=[("Audit files", "*.audit"), ("XML files", "*.xml"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            self.status_label.config(text="Parsing file...")
            self.root.update()
            
            self.current_data = self.parser.parse_audit_file(file_path)
            self.modified_items = set()
            
            if self.parser.all_fields:
                self.update_treeview_columns(self.parser.all_fields)
            
            self.update_display()
            
            self.export_btn.config(state=tk.NORMAL)
            self.export_audit_btn.config(state=tk.NORMAL)
            
            self.status_label.config(text=f"Successfully parsed {len(self.current_data)} checks from {os.path.basename(file_path)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse file: {str(e)}")
            self.status_label.config(text="Error parsing file")
    
    def update_display(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        columns = self.tree['columns']
        
        for i, check in enumerate(self.current_data):
            values = []
            for col in columns:
                if col == 'Check Number':
                    values.append(check['check_number'])
                else:
                    value = check.get(col, '')
                    if isinstance(value, str) and len(value) > 100:
                        if 'full_values' not in check:
                            check['full_values'] = {}
                        check['full_values'][col] = value
                        display_value = value[:97] + "..."
                        values.append(display_value)
                    else:
                        values.append(value)
            
            item_id = self.tree.insert('', 'end', values=values)
            
            check_number = check['check_number']
            if check_number in self.modified_items:
                self.tree.set(item_id, 'Check Number', f"*{values[0]}")
    
    def show_details(self, event):
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        check_number = item['values'][0]
        
        check_data = None
        for check in self.current_data:
            if check['check_number'] == check_number:
                check_data = check
                break
        
        if not check_data:
            return
        
        details_window = tk.Toplevel(self.root)
        details_window.title(f"Check Details - {check_number}")
        details_window.geometry("800x600")
        
        text_frame = ttk.Frame(details_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=('Consolas', 10))
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        details_text = f"Check Number: {check_data['check_number']}\n"
        details_text += f"Title: {check_data['title']}\n"
        details_text += f"Description: {check_data['description']}\n"
        details_text += f"Level: {check_data['level']}\n\n"
        
        exclude_fields = {'check_number', 'title', 'raw_content', 'attributes', 'level'}
        all_fields = [field for field in check_data.keys() if field not in exclude_fields]
        
        priority_fields = ['name', 'type', 'system', 'severity', 'required', 'info']
        command_fields = ['cmd', 'file', 'regex', 'search_locations', 'expect', 'not_expect']
        reference_fields = ['reference', 'see_also', 'solution']
        policy_fields = ['value_type', 'value_data', 'reg_key', 'reg_item', 'password_policy']
        wmi_fields = ['wmi_namespace', 'wmi_request', 'wmi_attribute', 'wmi_key']
        other_fields = [field for field in all_fields if field not in 
                       priority_fields + command_fields + reference_fields + policy_fields + wmi_fields]
        
        if any(field in check_data for field in priority_fields):
            details_text += "Basic Information:\n"
            for field in priority_fields:
                if field in check_data and check_data[field]:
                    details_text += f"{field.replace('_', ' ').title()}: {check_data[field]}\n"
            details_text += "\n"
        
        if any(field in check_data for field in command_fields):
            details_text += "Command/Execution:\n"
            for field in command_fields:
                if field in check_data and check_data[field]:
                    details_text += f"{field.replace('_', ' ').title()}: {check_data[field]}\n"
            details_text += "\n"
        
        if any(field in check_data for field in reference_fields):
            details_text += "References:\n"
            for field in reference_fields:
                if field in check_data and check_data[field]:
                    details_text += f"{field.replace('_', ' ').title()}: {check_data[field]}\n"
            details_text += "\n"
        
        if any(field in check_data for field in policy_fields):
            details_text += "Policy Settings:\n"
            for field in policy_fields:
                if field in check_data and check_data[field]:
                    details_text += f"{field.replace('_', ' ').title()}: {check_data[field]}\n"
            details_text += "\n"
        
        if any(field in check_data for field in wmi_fields):
            details_text += "WMI Queries:\n"
            for field in wmi_fields:
                if field in check_data and check_data[field]:
                    details_text += f"{field.replace('_', ' ').title()}: {check_data[field]}\n"
            details_text += "\n"
        
        if other_fields:
            details_text += "Additional Fields:\n"
            for field in sorted(other_fields):
                if field in check_data and check_data[field]:
                    details_text += f"{field.replace('_', ' ').title()}: {check_data[field]}\n"
        
        if check_data.get('attributes'):
            details_text += "\nAttributes:\n"
            for k, v in check_data.get('attributes', {}).items():
                details_text += f"  {k}: {v}\n"
        
        raw_content = check_data.get('raw_content', check_data.get('raw_xml', ''))
        if raw_content:
            details_text += f"\nRaw Content:\n{raw_content}"
        
        text_widget.insert(tk.END, details_text)
        text_widget.config(state=tk.DISABLED)
    
    # Exports current data to CSV
    def export_to_csv(self):
        if not self.current_data:
            messagebox.showwarning("Warning", "No data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save CSV file",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        progress_dialog = ProgressDialog(
            self.root, 
            "Exporting CSV File", 
            f"Exporting {len(self.current_data)} checks to CSV file..."
        )
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                exclude_fields = {'check_number', 'title', 'raw_content', 'attributes', 'level', 'full_values'}
                all_fields = set()
                for check in self.current_data:
                    all_fields.update(check.keys())
                
                fieldnames = ['Check Number'] + [field for field in sorted(all_fields) if field not in exclude_fields]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                total_checks = len(self.current_data)
                for i, check in enumerate(self.current_data):
                    progress_dialog.update_progress(i + 1, total_checks, f"Writing check {check['check_number']}...")
                    
                    row_data = {'Check Number': check['check_number']}
                    for field in fieldnames[1:]:  # Skip 'Check Number'
                        row_data[field] = check.get(field, '')
                    writer.writerow(row_data)
            
            progress_dialog.close()
            
            messagebox.showinfo("Success", f"Data exported successfully to {file_path}")
            self.status_label.config(text=f"Data exported to {os.path.basename(file_path)}")
            
        except Exception as e:
            progress_dialog.close()
            messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")
    
    def on_cell_click(self, event):
        if self.edit_entry:
            self.finish_edit()
        
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        
        if item and column:
            if column == '#1':
                return
            
            self.start_edit(item, column)
    
    def start_edit(self, item, column):
        values = self.tree.item(item, 'values')
        column_index = int(column[1:]) - 1
        
        if column_index < len(values):
            item_index = self.tree.index(item)
            if item_index < len(self.current_data):
                check_data = self.current_data[item_index]
                columns = self.tree['columns']
                if column_index < len(columns):
                    field_name = columns[column_index]
                    if field_name != 'Check Number':
                        if 'full_values' in check_data and field_name in check_data['full_values']:
                            current_value = check_data['full_values'][field_name]
                        else:
                            current_value = check_data.get(field_name, '')
                    else:
                        current_value = values[column_index]
                else:
                    current_value = values[column_index]
            else:
                current_value = values[column_index]
            
            bbox = self.tree.bbox(item, column)
            if bbox:
                self.edit_entry = tk.Entry(self.tree, font=('Arial', 9))
                self.edit_entry.place(x=bbox[0], y=bbox[1], width=bbox[2], height=bbox[3])
                self.edit_entry.insert(0, current_value)
                self.edit_entry.select_range(0, tk.END)
                self.edit_entry.focus()
                
                self.edit_entry.bind('<Return>', lambda e: self.finish_edit())
                self.edit_entry.bind('<Escape>', lambda e: self.cancel_edit())
                self.edit_entry.bind('<FocusOut>', lambda e: self.finish_edit())
                
                self.editing_item = item
                self.editing_column = column_index
    
    def finish_edit(self):
        if self.edit_entry and self.editing_item is not None:
            new_value = self.edit_entry.get()
            
            values = list(self.tree.item(self.editing_item, 'values'))
            if self.editing_column < len(values):
                values[self.editing_column] = new_value
                self.tree.item(self.editing_item, values=values)
            
            item_index = self.tree.index(self.editing_item)
            if item_index < len(self.current_data):
                columns = self.tree['columns']
                if self.editing_column < len(columns):
                    field_name = columns[self.editing_column]
                    if field_name != 'Check Number':
                        self.current_data[item_index][field_name] = new_value
                        if 'full_values' in self.current_data[item_index]:
                            self.current_data[item_index]['full_values'][field_name] = new_value
                        check_number = self.current_data[item_index]['check_number']
                        self.modified_items.add(check_number)
                        self.status_label.config(text=f"Check {check_number} modified - {len(self.modified_items)} checks changed")
            
            self.cancel_edit()
    
    def cancel_edit(self):
        if self.edit_entry:
            self.edit_entry.destroy()
            self.edit_entry = None
            self.editing_item = None
            self.editing_column = None
    
    def on_cell_edit(self, event):
        if event.keysym in ['Return', 'Escape']:
            if event.keysym == 'Return':
                self.finish_edit()
            else:
                self.cancel_edit()
    
    # Exports changes to .audit file
    def export_to_audit(self):
        if not self.current_data:
            messagebox.showwarning("Warning", "No data to export")
            return
        
        if not self.modified_items:
            messagebox.showinfo("Info", "No modifications detected. Exporting all data anyway.")
        
        file_path = filedialog.asksaveasfilename(
            title="Save .audit file",
            defaultextension=".audit",
            filetypes=[("Audit files", "*.audit"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        modified_data = self.parser.get_modified_checks(self.current_data)
        data_to_export = modified_data if modified_data else self.current_data
        
        progress_dialog = ProgressDialog(
            self.root, 
            "Exporting Audit File", 
            f"Exporting {len(data_to_export)} checks to .audit file..."
        )
        
        try:
            self.parser.process_audit_export(
                file_path, 
                data_to_export,
                progress_callback=progress_dialog.update_progress
            )
            
            progress_dialog.close()
            
            messagebox.showinfo("Success", f"Audit file exported successfully to {file_path}")
            self.status_label.config(text=f"Audit file exported to {os.path.basename(file_path)}")
            
        except Exception as e:
            progress_dialog.close()
            messagebox.showerror("Error", f"Failed to export .audit file: {str(e)}")
            self.status_label.config(text="Error exporting .audit file")
    
    def clear_data(self):
        self.current_data = []
        self.update_display()
        self.export_btn.config(state=tk.DISABLED)
        self.export_audit_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Ready to import .audit file")


def main():
    root = tk.Tk()
    app = AuditParserGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
