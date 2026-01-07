"""
Notes frame for managing encrypted markdown notes.
"""
import customtkinter as ctk
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM

class NotesFrame(ctk.CTkFrame):
    """Encrypted markdown note-taker with preview support."""
    
    def __init__(self, master, db_manager, app_instance, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        
        self.db = db_manager
        self.app = app_instance
        self.notes: List[Dict[str, Any]] = []
        self.selected_note_id: Optional[int] = None
        self.view_mode = "edit" # "edit" or "preview"
        
        # Split pane
        self.grid_columnconfigure(0, weight=1) # List
        self.grid_columnconfigure(1, weight=3) # Content
        self.grid_rowconfigure(0, weight=1)
        
        self._create_list_panel()
        self._create_content_panel()
        
        self.refresh()
    
    def _create_list_panel(self):
        """Create left panel with notes list."""
        self.list_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.list_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        # Header
        header = ctk.CTkFrame(self.list_frame, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=20)
        
        ctk.CTkLabel(
            header, text="My Notes",
            font=ctk.CTkFont(size=18, weight="bold")
        ).pack(side="left")
        
        self.add_btn = ctk.CTkButton(
            header, text="+ New Note", width=100, height=32,
            fg_color=COLOR_ACCENT, text_color="black",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._create_new_note
        )
        self.add_btn.pack(side="right")
        
        # Scrollable list
        self.list_scroll = ctk.CTkScrollableFrame(self.list_frame, fg_color="transparent")
        self.list_scroll.pack(fill="both", expand=True, padx=5, pady=5)
    
    def _create_content_panel(self):
        """Create right panel with editor/preview."""
        self.content_frame = ctk.CTkFrame(self, fg_color=COLOR_SURFACE, corner_radius=15)
        self.content_frame.grid(row=0, column=1, sticky="nsew")
        
        # Empty state
        self.empty_label = ctk.CTkLabel(
            self.content_frame,
            text="Select or create a note to begin writing.\nSupports basic markdown formatting and secure attachments.",
            text_color=COLOR_TEXT_DIM,
            font=ctk.CTkFont(size=14),
            wraplength=350
        )
        self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
        
        # Editor Container (hidden initially)
        self.editor_container = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        
        # Top toolbar
        toolbar = ctk.CTkFrame(self.editor_container, fg_color="transparent")
        toolbar.pack(fill="x", padx=25, pady=(20, 10))
        
        self.title_entry = ctk.CTkEntry(
            toolbar, placeholder_text="Note Title",
            font=ctk.CTkFont(size=20, weight="bold"),
            fg_color="transparent", border_width=0,
            height=40
        )
        self.title_entry.pack(side="left", fill="x", expand=True)
        
        # Attachments Button
        self.attach_btn = ctk.CTkButton(
            toolbar, text="📎 Attach", width=80, height=32,
            fg_color="#34495e", hover_color="#2c3e50",
            command=self._handle_add_attachment
        )
        self.attach_btn.pack(side="right", padx=5)

        # Mode Toggles
        mode_frame = ctk.CTkFrame(toolbar, fg_color=COLOR_BG, corner_radius=8)
        mode_frame.pack(side="right", padx=10)
        
        self.edit_mode_btn = ctk.CTkButton(
            mode_frame, text="Edit", width=60, height=30,
            fg_color=COLOR_ACCENT, text_color="black",
            corner_radius=6, command=lambda: self._set_mode("edit")
        )
        self.edit_mode_btn.pack(side="left", padx=2, pady=2)
        
        self.preview_mode_btn = ctk.CTkButton(
            mode_frame, text="Preview", width=70, height=30,
            fg_color="transparent", text_color=COLOR_TEXT,
            corner_radius=6, command=lambda: self._set_mode("preview")
        )
        self.preview_mode_btn.pack(side="left", padx=2, pady=2)

        self.delete_btn = ctk.CTkButton(
            toolbar, text="🗑", width=40, height=40,
            fg_color="transparent", text_color="#e74c3c",
            hover_color="#331111", font=ctk.CTkFont(size=18),
            command=self._delete_note
        )
        self.delete_btn.pack(side="right")
        
        # Main area with Editor + Attachments Panel
        main_editor_area = ctk.CTkFrame(self.editor_container, fg_color="transparent")
        main_editor_area.pack(fill="both", expand=True, padx=25, pady=(0, 25))
        
        # Editor
        self.editor_text = ctk.CTkTextbox(
            main_editor_area, 
            fg_color=COLOR_BG, border_color="#333333", border_width=1,
            font=ctk.CTkFont(family="Consolas", size=13),
            padx=20, pady=20
        )
        self.editor_text.pack(side="left", fill="both", expand=True)
        self.editor_text.bind("<<Modified>>", self._on_content_change)
        
        # Attachments Panel (Right side)
        self.att_panel = ctk.CTkFrame(main_editor_area, width=200, fg_color=COLOR_SURFACE, corner_radius=10)
        self.att_panel.pack(side="right", fill="y", padx=(10, 0))
        self.att_panel.pack_propagate(False)
        
        ctk.CTkLabel(self.att_panel, text="Attachments", font=ctk.CTkFont(size=12, weight="bold")).pack(pady=10)
        self.att_scroll = ctk.CTkScrollableFrame(self.att_panel, fg_color="transparent")
        self.att_scroll.pack(fill="both", expand=True, padx=5, pady=5)

        # Preview Area (Overlays editor when active)
        self.preview_text = ctk.CTkTextbox(
            main_editor_area,
            fg_color=COLOR_BG, border_color="#333333", border_width=1,
            font=ctk.CTkFont(size=13),
            padx=30, pady=30,
            state="disabled"
        )
        
        # Markdown Tags
        self.preview_text._textbox.tag_configure("h1", font=ctk.CTkFont(size=24, weight="bold"), foreground=COLOR_ACCENT)
        self.preview_text._textbox.tag_configure("h2", font=ctk.CTkFont(size=20, weight="bold"), foreground="#27ae60")
        self.preview_text._textbox.tag_configure("h3", font=ctk.CTkFont(size=16, weight="bold"), foreground="#2ecc71")
        self.preview_text._textbox.tag_configure("bold", font=ctk.CTkFont(weight="bold"), foreground=COLOR_TEXT)
        self.preview_text._textbox.tag_configure("italic", font=ctk.CTkFont(slant="italic"), foreground=COLOR_TEXT)
        self.preview_text._textbox.tag_configure("code", font=ctk.CTkFont(family="Consolas"), background="#222222", foreground=COLOR_ACCENT)
        self.preview_text._textbox.tag_configure("dim", foreground=COLOR_TEXT_DIM)
    
    def refresh(self):
        """Reload notes from database."""
        self.notes = self.db.get_all_notes()
        self._update_list()
        
    def _update_list(self):
        for widget in self.list_scroll.winfo_children():
            widget.destroy()
            
        for note in self.notes:
            self._create_list_item(note)
            
        if not self.notes:
            ctk.CTkLabel(
                self.list_scroll, text="No notes yet",
                text_color=COLOR_TEXT_DIM, pady=40
            ).pack()
            
    def _create_list_item(self, note: Dict[str, Any]):
        is_selected = self.selected_note_id == note['id']
        bg_color = "#333333" if is_selected else "transparent"
        
        item = ctk.CTkFrame(self.list_scroll, height=60, fg_color=bg_color, cursor="hand2", corner_radius=10)
        item.pack(fill="x", pady=2, padx=5)
        item.pack_propagate(False)
        
        content = ctk.CTkFrame(item, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=8)
        
        ctk.CTkLabel(
            content, text=note['title'] or "Untitled Note",
            font=ctk.CTkFont(size=14, weight="bold" if is_selected else "normal"),
            anchor="w", text_color=COLOR_TEXT
        ).pack(fill="x")
        
        date_str = note['updated_at'].split()[0] if note['updated_at'] else ""
        ctk.CTkLabel(
            content, text=f"Last edited: {date_str}",
            font=ctk.CTkFont(size=10),
            text_color=COLOR_TEXT_DIM, anchor="w"
        ).pack(fill="x")
        
        def handle_click(e):
            self._select_note(note['id'])
            
        for widget in [item, content] + list(content.winfo_children()):
            widget.bind("<Button-1>", handle_click)

    def _select_note(self, note_id: int):
        self.selected_note_id = note_id
        note = self.db.get_note(note_id)
        if not note: return
        
        self.empty_label.place_forget()
        self.editor_container.pack(fill="both", expand=True)
        
        self.title_entry.delete(0, "end")
        self.title_entry.insert(0, note['title'])
        
        self.editor_text.configure(state="normal")
        self.editor_text.delete("1.0", "end")
        self.editor_text.insert("1.0", note['content'] or "")
        self.editor_text.edit_modified(False)
        
        self._display_attachments()
        self._set_mode("edit")
        self._update_list()

    def _handle_add_attachment(self):
        if not self.selected_note_id: return
        
        from tkinter import filedialog
        file_path = filedialog.askopenfilename()
        if not file_path: return
        
        try:
            p = Path(file_path)
            with open(file_path, "rb") as f:
                data = f.read()
            
            # 1. Store in BlobManager
            if not self.app.blob_mgr:
                print("Blob manager not initialized")
                return
                
            blob_id = self.app.blob_mgr.store_blob(p.name, p.suffix, data)
            
            # 2. Save link in main DB
            self.db.add_attachment(self.selected_note_id, blob_id, p.name, p.suffix)
            
            self._display_attachments()
        except Exception as e:
            print(f"Attachment failed: {e}")

    def _display_attachments(self):
        """Show list of attached files for current note."""
        for widget in self.att_scroll.winfo_children():
            widget.destroy()
            
        if not self.selected_note_id: return
        
        atts = self.db.get_attachments(self.selected_note_id)
        for att in atts:
            self._create_attachment_item(att)
            
        if not atts:
            ctk.CTkLabel(
                self.att_scroll, text="No files",
                text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=10)
            ).pack(pady=20)

    def _create_attachment_item(self, att: Dict[str, Any]):
        item = ctk.CTkFrame(self.att_scroll, fg_color=COLOR_BG, height=45)
        item.pack(fill="x", pady=2)
        item.pack_propagate(False)
        
        # Icon/Label
        icon = "🖼" if att['file_type'].lower() in ['.jpg', '.png', '.gif', '.jpeg'] else "📄"
        label = ctk.CTkLabel(item, text=f"{icon} {att['filename']}", font=ctk.CTkFont(size=11), anchor="w")
        label.pack(side="left", fill="x", expand=True, padx=10)
        
        # Download button
        ctk.CTkButton(
            item, text="💾", width=30, height=30,
            fg_color="transparent", hover_color="#333333",
            command=lambda: self._handle_download_attachment(att)
        ).pack(side="right", padx=2)
        
        # Delete button
        ctk.CTkButton(
            item, text="🗑", width=30, height=30,
            fg_color="transparent", text_color="#e74c3c", hover_color="#331111",
            command=lambda: self._handle_delete_attachment(att)
        ).pack(side="right", padx=2)

    def _handle_download_attachment(self, att: Dict[str, Any]):
        try:
            blob = self.app.blob_mgr.retrieve_blob(att['blob_id'])
            if not blob: return
            
            from tkinter import filedialog
            save_path = filedialog.asksaveasfilename(initialfile=att['filename'])
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(blob['content'])
        except Exception as e:
            print(f"Download failed: {e}")

    def _handle_delete_attachment(self, att: Dict[str, Any]):
        self.db.delete_attachment(att['id'])
        # Optional: delete blob if not used elsewhere, but for simplicity we keep blobs for now
        # self.app.blob_mgr.delete_blob(att['blob_id']) 
        self._display_attachments()

    def _create_new_note(self):
        new_id = self.db.add_note("New Note", "")
        self.refresh()
        self._select_note(new_id)

    def _on_content_change(self, event=None):
        if self.editor_text.edit_modified():
            self._save_current_note()
            self.editor_text.edit_modified(False)

    def _save_current_note(self):
        if self.selected_note_id:
            title = self.title_entry.get()
            content = self.editor_text.get("1.0", "end-1c")
            self.db.update_note(self.selected_note_id, title, content)
            # Potentially update list title if it changed
            # For performance, maybe only update list on focus lose or specific interval

    def _delete_note(self):
        if self.selected_note_id:
            self.db.delete_note(self.selected_note_id)
            self.selected_note_id = None
            self.editor_container.pack_forget()
            self.empty_label.place(relx=0.5, rely=0.5, anchor="center")
            self.refresh()

    def _set_mode(self, mode: str):
        self.view_mode = mode
        if mode == "edit":
            self.preview_text.pack_forget()
            self.editor_text.pack(fill="both", expand=True, padx=25, pady=(0, 25))
            self.edit_mode_btn.configure(fg_color=COLOR_ACCENT, text_color="black")
            self.preview_mode_btn.configure(fg_color="transparent", text_color=COLOR_TEXT)
        else:
            self._save_current_note()
            self.editor_text.pack_forget()
            self.preview_text.pack(fill="both", expand=True, padx=25, pady=(0, 25))
            self.edit_mode_btn.configure(fg_color="transparent", text_color=COLOR_TEXT)
            self.preview_mode_btn.configure(fg_color=COLOR_ACCENT, text_color="black")
            self._render_preview()

    def _render_preview(self):
        content = self.editor_text.get("1.0", "end-1c")
        self.preview_text.configure(state="normal")
        self.preview_text.delete("1.0", "end")
        
        lines = content.splitlines()
        for line in lines:
            # 1. Headers
            if line.startswith("# "):
                self._insert_styled(line[2:], "h1")
            elif line.startswith("## "):
                self._insert_styled(line[3:], "h2")
            elif line.startswith("### "):
                self._insert_styled(line[4:], "h3")
            # 2. Lists
            elif line.strip().startswith("- ") or line.strip().startswith("* "):
                self.preview_text.insert("end", "  • ", "bold")
                self._insert_inline_styles(line.strip()[2:])
                self.preview_text.insert("end", "\n")
            # 3. Horizontal Rule
            elif line.strip() in ["---", "***", "___"]:
                self.preview_text.insert("end", "—" * 40 + "\n", "dim")
            # 4. Normal text
            else:
                if line.strip() == "":
                    self.preview_text.insert("end", "\n")
                else:
                    self._insert_inline_styles(line)
                    self.preview_text.insert("end", "\n")
                
        self.preview_text.configure(state="disabled")

    def _insert_styled(self, text, tag):
        """Insert text with a specific block tag."""
        self.preview_text.insert("end", text + "\n", tag)
        self.preview_text.insert("end", "\n") # Extra spacing for headers

    def _insert_inline_styles(self, text):
        """Parse and insert text with inline styles (bold, italic, code)."""
        # This is a simple non-nested parser
        parts = re.split(r'(\*\*.*?\*\*|\*.*?\*|`.*?`)', text)
        for part in parts:
            if part.startswith("**") and part.endswith("**"):
                self.preview_text.insert("end", part[2:-2], "bold")
            elif part.startswith("*") and part.endswith("*"):
                self.preview_text.insert("end", part[1:-1], "italic")
            elif part.startswith("`") and part.endswith("`"):
                self.preview_text.insert("end", part[1:-1], "code")
            else:
                self.preview_text.insert("end", part)
