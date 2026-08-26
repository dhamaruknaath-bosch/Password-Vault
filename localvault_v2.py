import base64
import hashlib
import os
import secrets
import sqlite3
import string
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

APP_NAME = "LocalVault"
APP_VERSION = "2.0"
DATA_DIR = Path(os.getenv("LOCALAPPDATA", Path.home())) / APP_NAME
DB_PATH = DATA_DIR / "vault.db"
DEFAULT_CLIPBOARD_SECONDS = 20

DARK = {"bg":"#0f172a","panel":"#111827","field":"#1f2937","fg":"#e5e7eb","muted":"#94a3b8","accent":"#6366f1","select":"#312e81"}
LIGHT = {"bg":"#f1f5f9","panel":"#ffffff","field":"#e2e8f0","fg":"#0f172a","muted":"#475569","accent":"#4f46e5","select":"#c7d2fe"}

def b64e(data): return base64.urlsafe_b64encode(data).decode("ascii")
def b64d(data): return base64.urlsafe_b64decode(data.encode("ascii"))
def kdf(secret, salt):
    return hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**15, r=8, p=1, dklen=32, maxmem=64*1024*1024)
def seal(key, data):
    if isinstance(data, str): data=data.encode("utf-8")
    nonce=os.urandom(12)
    return b64e(nonce+AESGCM(key).encrypt(nonce,data,None))
def open_seal(key, token, raw=False):
    blob=b64d(token); out=AESGCM(key).decrypt(blob[:12],blob[12:],None)
    return out if raw else out.decode("utf-8")

class DB:
    def __init__(self):
        DATA_DIR.mkdir(parents=True,exist_ok=True)
        self.con=sqlite3.connect(DB_PATH); self.con.row_factory=sqlite3.Row
        self.con.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS credentials(
          id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,username TEXT NOT NULL,
          password TEXT NOT NULL,website TEXT NOT NULL,category TEXT NOT NULL,notes TEXT NOT NULL,
          created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
        """); self.con.commit()
    def get(self,table,key,default=None):
        row=self.con.execute(f"SELECT value FROM {table} WHERE key=?",(key,)).fetchone()
        return row[0] if row else default
    def put(self,table,key,value):
        self.con.execute(f"INSERT OR REPLACE INTO {table}(key,value) VALUES(?,?)",(key,str(value))); self.con.commit()
    def rows(self): return self.con.execute("SELECT * FROM credentials ORDER BY title COLLATE NOCASE").fetchall()
    def add(self,v):
        now=int(time.time()); self.con.execute("INSERT INTO credentials(title,username,password,website,category,notes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",(*v,now,now)); self.con.commit()
    def update(self,i,v): self.con.execute("UPDATE credentials SET title=?,username=?,password=?,website=?,category=?,notes=?,updated_at=? WHERE id=?",(*v,int(time.time()),i)); self.con.commit()
    def delete(self,i): self.con.execute("DELETE FROM credentials WHERE id=?",(i,)); self.con.commit()

class CredentialDialog(tk.Toplevel):
    def __init__(self,parent,title,initial=None):
        super().__init__(parent); self.title(title); self.result=None; self.transient(parent); self.grab_set(); self.resizable(False,False)
        initial=initial or {}; self.vars={k:tk.StringVar(value=initial.get(k,"")) for k in ("title","username","password","website","category")}
        f=ttk.Frame(self,padding=18); f.grid()
        for r,(k,label) in enumerate((("title","Title"),("username","Username"),("password","Password"),("website","Website"),("category","Category"))):
            ttk.Label(f,text=label).grid(row=r,column=0,sticky="w",pady=6,padx=(0,12)); ttk.Entry(f,textvariable=self.vars[k],width=43,show="*" if k=="password" else "").grid(row=r,column=1,pady=6)
            if k=="password": ttk.Button(f,text="Generate",command=self.generate).grid(row=r,column=2,padx=(8,0))
        ttk.Label(f,text="Notes").grid(row=5,column=0,sticky="nw",pady=6); self.notes=tk.Text(f,width=43,height=5); self.notes.insert("1.0",initial.get("notes","")); self.notes.grid(row=5,column=1,pady=6)
        b=ttk.Frame(f); b.grid(row=6,column=0,columnspan=3,sticky="e",pady=(12,0)); ttk.Button(b,text="Cancel",command=self.destroy).pack(side="left",padx=5); ttk.Button(b,text="Save",command=self.save).pack(side="left")
        self.bind("<Escape>",lambda e:self.destroy()); self.wait_visibility(); self.focus_force()
    def generate(self):
        chars=string.ascii_letters+string.digits+"!@#$%^&*()-_=+"
        self.vars["password"].set("".join(secrets.choice(chars) for _ in range(20)))
    def save(self):
        if not self.vars["title"].get().strip() or not self.vars["password"].get(): messagebox.showwarning("Required","Title and password are required.",parent=self); return
        self.result=tuple(self.vars[k].get().strip() if k!="password" else self.vars[k].get() for k in ("title","username","password","website","category"))+(self.notes.get("1.0","end-1c").strip(),); self.destroy()

class SettingsDialog(tk.Toplevel):
    def __init__(self,parent):
        super().__init__(parent); self.app=parent; self.title("Settings"); self.result=None; self.transient(parent); self.grab_set(); self.resizable(False,False)
        self.theme=tk.StringVar(value=parent.db.get("settings","theme","dark")); self.enabled=tk.BooleanVar(value=parent.db.get("settings","autolock_enabled","1")=="1"); self.minutes=tk.StringVar(value=parent.db.get("settings","autolock_minutes","5"))
        f=ttk.Frame(self,padding=20); f.grid(); ttk.Label(f,text="Theme").grid(row=0,column=0,sticky="w",pady=8); ttk.Combobox(f,textvariable=self.theme,values=("dark","light"),state="readonly",width=18).grid(row=0,column=1,pady=8)
        ttk.Checkbutton(f,text="Enable inactivity auto-lock",variable=self.enabled).grid(row=1,column=0,columnspan=2,sticky="w",pady=8)
        ttk.Label(f,text="Auto-lock after minutes").grid(row=2,column=0,sticky="w",pady=8,padx=(0,12)); ttk.Spinbox(f,from_=1,to=120,textvariable=self.minutes,width=8).grid(row=2,column=1,sticky="w")
        ttk.Separator(f).grid(row=3,column=0,columnspan=2,sticky="ew",pady=10)
        ttk.Button(f,text="Change master password",command=self.change_master).grid(row=4,column=0,columnspan=2,sticky="ew",pady=4)
        ttk.Button(f,text="Change PIN",command=self.change_pin).grid(row=5,column=0,columnspan=2,sticky="ew",pady=4)
        ttk.Label(f,text="Theme and timer settings are kept on this PC.").grid(row=6,column=0,columnspan=2,pady=(8,14))
        b=ttk.Frame(f); b.grid(row=7,column=0,columnspan=2,sticky="e"); ttk.Button(b,text="Cancel",command=self.destroy).pack(side="left",padx=5); ttk.Button(b,text="Save",command=self.save).pack(side="left")
    def change_master(self):
        new1=simpledialog.askstring("New master password","Enter new master password:",show="*",parent=self)
        if not new1: return
        if new1!=simpledialog.askstring("Confirm","Confirm new master password:",show="*",parent=self): messagebox.showerror("Mismatch","Passwords do not match.",parent=self); return
        ms=os.urandom(16); self.app.db.put("meta","master_salt",b64e(ms)); self.app.db.put("meta","master_wrap",seal(kdf(new1,ms),self.app.data_key)); self.app.db.put("meta","master_check",seal(kdf(new1,ms),"ADMIN_OK"))
        messagebox.showinfo("Updated","Master password changed.",parent=self)
    def change_pin(self):
        new1=simpledialog.askstring("New PIN","Enter new 6-8 digit PIN:",show="*",parent=self)
        if not new1: return
        if not(new1.isdigit() and 6<=len(new1)<=8): messagebox.showwarning("Invalid PIN","PIN must contain 6 to 8 digits.",parent=self); return
        if new1!=simpledialog.askstring("Confirm","Confirm new PIN:",show="*",parent=self): messagebox.showerror("Mismatch","PINs do not match.",parent=self); return
        ps=os.urandom(16); self.app.db.put("meta","pin_salt",b64e(ps)); self.app.db.put("meta","pin_wrap",seal(kdf(new1,ps),self.app.data_key))
        messagebox.showinfo("Updated","PIN changed.",parent=self)
    def save(self):
        try: m=int(self.minutes.get()); assert 1<=m<=120
        except Exception: messagebox.showwarning("Invalid value","Choose 1 to 120 minutes.",parent=self); return
        self.result=(self.theme.get(),self.enabled.get(),m); self.destroy()

class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.db=DB(); self.data_key=None; self.rows={}; self.lock_job=None; self.clip_job=None; self.failed=0
        self.title(f"{APP_NAME} {APP_VERSION}"); self.minsize(850,540); self.geometry(self.db.get("settings","geometry","1000x650")); self.protocol("WM_DELETE_WINDOW",self.close)
        self.style=ttk.Style(self); self.style.theme_use("clam"); self.apply_theme(); self.show_login()
    def apply_theme(self):
        c=LIGHT if self.db.get("settings","theme","dark")=="light" else DARK; self.colors=c; self.configure(bg=c["bg"])
        self.style.configure("TFrame",background=c["bg"]); self.style.configure("TLabel",background=c["bg"],foreground=c["fg"]); self.style.configure("TCheckbutton",background=c["bg"],foreground=c["fg"])
        self.style.configure("TButton",padding=8); self.style.configure("TEntry",fieldbackground=c["panel"],foreground=c["fg"]); self.style.configure("TCombobox",fieldbackground=c["panel"],foreground=c["fg"])
        self.style.configure("Treeview",rowheight=30,background=c["panel"],fieldbackground=c["panel"],foreground=c["fg"]); self.style.configure("Treeview.Heading",background=c["field"],foreground=c["fg"]); self.style.map("Treeview",background=[("selected",c["select"])])
    def clear(self):
        for w in self.winfo_children(): w.destroy()
    def show_login(self):
        self.clear(); self.data_key=None; setup=self.db.get("meta","master_salt") is None
        f=ttk.Frame(self,padding=40); f.place(relx=.5,rely=.5,anchor="center"); ttk.Label(f,text="LocalVault",font=("Segoe UI",24,"bold")).grid(row=0,column=0,columnspan=2,pady=(0,8))
        if setup: self.setup_form(f)
        else: self.login_form(f)
    def setup_form(self,f):
        ttk.Label(f,text="Create master password and a 6-8 digit quick-unlock PIN").grid(row=1,column=0,columnspan=2,pady=(0,15)); self.master_pw=tk.StringVar(); self.master2=tk.StringVar(); self.pin=tk.StringVar(); self.pin2=tk.StringVar()
        for r,(label,var) in enumerate((("Master password",self.master_pw),("Confirm master",self.master2),("Quick PIN",self.pin),("Confirm PIN",self.pin2)),2): ttk.Label(f,text=label).grid(row=r,column=0,sticky="w",pady=5,padx=(0,10)); ttk.Entry(f,textvariable=var,show="*",width=28).grid(row=r,column=1,pady=5)
        ttk.Button(f,text="Create vault",command=self.create_vault).grid(row=6,column=0,columnspan=2,sticky="ew",pady=16); ttk.Label(f,text="No forced master-password length. A strong passphrase is still recommended.").grid(row=7,column=0,columnspan=2)
    def create_vault(self):
        master=self.master_pw.get(); pin=self.pin.get()
        if not master: messagebox.showwarning("Required","Master password cannot be empty."); return
        if master!=self.master2.get(): messagebox.showerror("Mismatch","Master passwords do not match."); return
        if not(pin.isdigit() and 6<=len(pin)<=8): messagebox.showwarning("Invalid PIN","PIN must contain 6 to 8 digits."); return
        if pin!=self.pin2.get(): messagebox.showerror("Mismatch","PINs do not match."); return
        data_key=os.urandom(32); ms=os.urandom(16); ps=os.urandom(16)
        self.db.put("meta","master_salt",b64e(ms)); self.db.put("meta","pin_salt",b64e(ps)); self.db.put("meta","master_wrap",seal(kdf(master,ms),data_key)); self.db.put("meta","pin_wrap",seal(kdf(pin,ps),data_key)); self.db.put("meta","master_check",seal(kdf(master,ms),"ADMIN_OK"))
        for k,v in (("theme","dark"),("autolock_enabled","1"),("autolock_minutes","5")): self.db.put("settings",k,v)
        self.data_key=data_key; self.build_main()
    def login_form(self,f):
        ttk.Label(f,text="Quick unlock with PIN, or use the master password").grid(row=1,column=0,columnspan=2,pady=(0,15)); self.secret=tk.StringVar(); self.mode=tk.StringVar(value="PIN")
        ttk.Radiobutton(f,text="PIN",variable=self.mode,value="PIN").grid(row=2,column=0); ttk.Radiobutton(f,text="Master password",variable=self.mode,value="MASTER").grid(row=2,column=1)
        e=ttk.Entry(f,textvariable=self.secret,show="*",width=32); e.grid(row=3,column=0,columnspan=2,pady=10); e.focus(); ttk.Button(f,text="Unlock",command=self.unlock).grid(row=4,column=0,columnspan=2,sticky="ew",pady=8); self.bind("<Return>",lambda e:self.unlock())
    def unlock(self):
        if self.failed: time.sleep(min(self.failed,5))
        try:
            if self.mode.get()=="PIN": salt=b64d(self.db.get("meta","pin_salt")); wrap=self.db.get("meta","pin_wrap")
            else: salt=b64d(self.db.get("meta","master_salt")); wrap=self.db.get("meta","master_wrap")
            self.data_key=open_seal(kdf(self.secret.get(),salt),wrap,raw=True); self.failed=0; self.unbind("<Return>"); self.build_main()
        except Exception: self.failed+=1; messagebox.showerror("Unlock failed","Incorrect credential. Repeated failures are delayed.")
    def authorize(self):
        master=simpledialog.askstring("Master authorization","Enter the master password for this change:",show="*",parent=self)
        if master is None: return False
        try:
            key=kdf(master,b64d(self.db.get("meta","master_salt")))
            return open_seal(key,self.db.get("meta","master_check"))=="ADMIN_OK"
        except Exception: messagebox.showerror("Not authorized","Incorrect master password."); return False
    def build_main(self):
        self.clear(); self.apply_theme(); top=ttk.Frame(self,padding=14); top.pack(fill="x"); ttk.Label(top,text="Password Vault",font=("Segoe UI",20,"bold")).pack(side="left")
        for text,cmd in (("Lock",self.lock),("Settings",self.settings),("Backup",self.backup),("Add",self.add)): ttk.Button(top,text=text,command=cmd).pack(side="right",padx=4)
        s=ttk.Frame(self,padding=(14,0,14,10)); s.pack(fill="x"); ttk.Label(s,text="Search").pack(side="left",padx=(0,8)); self.query=tk.StringVar(); self.query.trace_add("write",lambda *_:self.refresh()); ttk.Entry(s,textvariable=self.query).pack(fill="x",expand=True)
        body=ttk.Frame(self,padding=(14,0,14,14)); body.pack(fill="both",expand=True); self.tree=ttk.Treeview(body,columns=("title","username","password","website","category"),show="headings")
        for k,t,w in (("title","Title",180),("username","Username",200),("password","Password",200),("website","Website",200),("category","Category",120)): self.tree.heading(k,text=t); self.tree.column(k,width=w)
        self.tree.heading("password",text="Password \U0001F441",command=self.toggle_passwords)
        self.tree.pack(side="left",fill="both",expand=True); self.tree.bind("<<TreeviewSelect>>",lambda e:self.details()); self.tree.bind("<Double-1>",lambda e:self.edit())
        side=ttk.Frame(body,padding=(18,8)); side.pack(side="right",fill="y"); self.detail=ttk.Label(side,text="Select a credential",justify="left",wraplength=280); self.detail.pack(anchor="w",pady=(0,14))
        for text,cmd in (("Copy username",lambda:self.copy("username")),("Copy password",lambda:self.copy("password")),("Edit",self.edit),("Delete",self.delete)): ttk.Button(side,text=text,command=cmd,width=22).pack(fill="x",pady=4)
        self.bind_all("<Any-KeyPress>",lambda e:self.reset_timer(),add="+"); self.bind_all("<Any-Button>",lambda e:self.reset_timer(),add="+"); self.show_passwords=False; self.refresh(); self.reset_timer()
    def toggle_passwords(self):
        self.show_passwords=not self.show_passwords; self.tree.heading("password",text="Password \U0001F441" if not self.show_passwords else "Password \U0001F576"); self.refresh()
    def decode(self,r): return {k:(open_seal(self.data_key,r[k]) if k in ("username","password","website","notes") else r[k]) for k in r.keys()}
    def encrypt_values(self,v): return (v[0],seal(self.data_key,v[1]),seal(self.data_key,v[2]),seal(self.data_key,v[3]),v[4],seal(self.data_key,v[5]))
    def refresh(self):
        self.tree.delete(*self.tree.get_children()); self.rows={}; q=self.query.get().lower().strip()
        for r in self.db.rows():
            try: d=self.decode(r)
            except Exception: continue
            if q and q not in " ".join((d["title"],d["username"],d["website"],d["category"])).lower(): continue
            i=str(d["id"]); self.rows[i]=d; pw=d["password"] if self.show_passwords else "*"*len(d["password"]); self.tree.insert("","end",iid=i,values=(d["title"],d["username"],pw,d["website"],d["category"]))
    def selected(self):
        s=self.tree.selection(); return self.rows.get(s[0]) if s else None
    def details(self):
        d=self.selected(); self.detail.config(text=(f'{d["title"]}\n\nUsername: {d["username"]}\nWebsite: {d["website"] or "-"}\nCategory: {d["category"] or "-"}\n\nNotes:\n{d["notes"] or "-"}' if d else "Select a credential"))
    def add(self):
        if not self.authorize(): return
        x=CredentialDialog(self,"Add credential"); self.wait_window(x)
        if x.result: self.db.add(self.encrypt_values(x.result)); self.refresh()
    def edit(self):
        d=self.selected()
        if not d or not self.authorize(): return
        x=CredentialDialog(self,"Edit credential",{k:d[k] for k in ("title","username","password","website","category","notes")}); self.wait_window(x)
        if x.result: self.db.update(d["id"],self.encrypt_values(x.result)); self.refresh()
    def delete(self):
        d=self.selected()
        if not d or not self.authorize(): return
        if messagebox.askyesno("Delete",f'Delete "{d["title"]}" permanently?'): self.db.delete(d["id"]); self.refresh(); self.detail.config(text="Select a credential")
    def copy(self,k):
        d=self.selected()
        if not d: return
        self.clipboard_clear(); self.clipboard_append(d[k]); self.update(); messagebox.showinfo("Copied",f"{k.title()} copied.")
    def settings(self):
        if not self.authorize(): return
        x=SettingsDialog(self); self.wait_window(x)
        if x.result:
            theme,enabled,minutes=x.result; self.db.put("settings","theme",theme); self.db.put("settings","autolock_enabled","1" if enabled else "0"); self.db.put("settings","autolock_minutes",minutes); self.apply_theme(); self.build_main()
    def reset_timer(self):
        if self.lock_job:
            try: self.after_cancel(self.lock_job)
            except Exception: pass
        self.lock_job=None
        if self.data_key and self.db.get("settings","autolock_enabled","1")=="1": self.lock_job=self.after(int(self.db.get("settings","autolock_minutes","5"))*60000,self.lock)
    def backup(self):
        if not self.authorize(): return
        path=filedialog.asksaveasfilename(defaultextension=".db",filetypes=[("LocalVault database","*.db")],initialfile="localvault_backup.db")
        if path: dest=sqlite3.connect(path); self.db.con.backup(dest); dest.close(); messagebox.showinfo("Backup complete","Encrypted app database and settings were backed up.")
    def lock(self): self.show_login()
    def close(self):
        self.db.put("settings","geometry",self.geometry()); self.db.con.close(); self.destroy()

if __name__=="__main__": App().mainloop()
