import tkinter as tk
from tkinter import messagebox
import hashlib
import secrets
import string
import base64
import pyperclip


# =========================
# SECURITY FUNCTIONS
# =========================

def hash_password(password):
    """Create a secure salted PBKDF2 hash."""
    salt = secrets.token_bytes(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200_000
    )

    return (
        base64.b64encode(salt).decode()
        + "$"
        + base64.b64encode(hashed).decode()
    )


def verify_password(password, stored_hash):
    """Verify password against stored PBKDF2 hash."""
    try:
        salt_b64, hash_b64 = stored_hash.split("$")

        salt = base64.b64decode(salt_b64)
        stored = base64.b64decode(hash_b64)

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            200_000
        )

        return secrets.compare_digest(new_hash, stored)

    except Exception:
        return False


def generate_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation

    return "".join(
        secrets.choice(characters)
        for _ in range(length)
    )


def password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1

    if len(password) >= 12:
        score += 1

    if any(c.islower() for c in password):
        score += 1

    if any(c.isupper() for c in password):
        score += 1

    if any(c.isdigit() for c in password):
        score += 1

    if any(c in string.punctuation for c in password):
        score += 1

    if score <= 2:
        return "Weak"

    elif score <= 4:
        return "Medium"

    else:
        return "Strong"


# =========================
# MAIN APPLICATION
# =========================

class PasswordSecurityTool:

    def __init__(self, root):

        self.root = root

        self.root.title("Password Security Tool")
        self.root.geometry("850x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#101114")

        self.build_ui()


    # =========================
    # UI
    # =========================

    def build_ui(self):

        # Title
        tk.Label(
            self.root,
            text="PASSWORD SECURITY TOOL",
            font=("Segoe UI", 25, "bold"),
            fg="white",
            bg="#101114"
        ).pack(pady=(25, 5))

        tk.Label(
            self.root,
            text="Generate • Hash • Verify • Analyze",
            font=("Segoe UI", 11),
            fg="#999999",
            bg="#101114"
        ).pack()


        # Main container
        main = tk.Frame(
            self.root,
            bg="#1b1d22"
        )

        main.pack(
            fill="both",
            expand=True,
            padx=40,
            pady=25
        )


        # =========================
        # LEFT SIDE
        # =========================

        left = tk.Frame(
            main,
            bg="#1b1d22"
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=25,
            pady=25
        )


        tk.Label(
            left,
            text="PASSWORD",
            font=("Segoe UI", 11, "bold"),
            fg="#bbbbbb",
            bg="#1b1d22"
        ).pack(anchor="w")


        self.password_entry = tk.Entry(
            left,
            font=("Segoe UI", 13),
            bg="#292c32",
            fg="white",
            insertbackground="white",
            relief="flat",
            show="•"
        )

        self.password_entry.pack(
            fill="x",
            pady=(8, 15),
            ipady=10
        )


        # Show password
        self.show_password = tk.BooleanVar()

        tk.Checkbutton(
            left,
            text="Show Password",
            variable=self.show_password,
            command=self.toggle_password,
            bg="#1b1d22",
            fg="#aaaaaa",
            selectcolor="#1b1d22",
            activebackground="#1b1d22",
            activeforeground="white"
        ).pack(anchor="w")


        # Strength
        tk.Label(
            left,
            text="PASSWORD STRENGTH",
            font=("Segoe UI", 10, "bold"),
            fg="#bbbbbb",
            bg="#1b1d22"
        ).pack(
            anchor="w",
            pady=(25, 8)
        )


        self.strength_label = tk.Label(
            left,
            text="—",
            font=("Segoe UI", 14, "bold"),
            fg="#aaaaaa",
            bg="#1b1d22"
        )

        self.strength_label.pack(anchor="w")


        tk.Button(
            left,
            text="CHECK STRENGTH",
            command=self.check_strength,
            font=("Segoe UI", 10, "bold"),
            bg="#4f46e5",
            fg="white",
            activebackground="#6366f1",
            relief="flat",
            cursor="hand2",
            width=25,
            pady=9
        ).pack(pady=15)


        # Hash
        tk.Button(
            left,
            text="GENERATE SECURE HASH",
            command=self.create_hash,
            font=("Segoe UI", 10, "bold"),
            bg="#2563eb",
            fg="white",
            activebackground="#3b82f6",
            relief="flat",
            cursor="hand2",
            width=25,
            pady=9
        ).pack(pady=5)


        # Verify
        tk.Button(
            left,
            text="VERIFY PASSWORD",
            command=self.verify,
            font=("Segoe UI", 10, "bold"),
            bg="#16a34a",
            fg="white",
            activebackground="#22c55e",
            relief="flat",
            cursor="hand2",
            width=25,
            pady=9
        ).pack(pady=5)


        # =========================
        # RIGHT SIDE
        # =========================

        right = tk.Frame(
            main,
            bg="#1b1d22"
        )

        right.pack(
            side="right",
            fill="both",
            expand=True,
            padx=25,
            pady=25
        )


        tk.Label(
            right,
            text="PASSWORD GENERATOR",
            font=("Segoe UI", 11, "bold"),
            fg="#bbbbbb",
            bg="#1b1d22"
        ).pack(anchor="w")


        # Length
        tk.Label(
            right,
            text="Length",
            fg="white",
            bg="#1b1d22",
            font=("Segoe UI", 10)
        ).pack(
            anchor="w",
            pady=(15, 0)
        )


        self.length_slider = tk.Scale(
            right,
            from_=8,
            to=40,
            orient="horizontal",
            bg="#1b1d22",
            fg="white",
            troughcolor="#33363d",
            activebackground="#6366f1",
            highlightthickness=0
        )

        self.length_slider.set(16)

        self.length_slider.pack(
            fill="x"
        )


        # Generated password
        self.generated_entry = tk.Entry(
            right,
            font=("Segoe UI", 11),
            bg="#292c32",
            fg="#00ff88",
            insertbackground="white",
            relief="flat"
        )

        self.generated_entry.pack(
            fill="x",
            pady=15,
            ipady=10
        )


        tk.Button(
            right,
            text="GENERATE PASSWORD",
            command=self.generate,
            font=("Segoe UI", 10, "bold"),
            bg="#9333ea",
            fg="white",
            activebackground="#a855f7",
            relief="flat",
            cursor="hand2",
            width=25,
            pady=10
        ).pack(pady=5)


        tk.Button(
            right,
            text="COPY PASSWORD",
            command=self.copy_password,
            font=("Segoe UI", 10, "bold"),
            bg="#374151",
            fg="white",
            activebackground="#4b5563",
            relief="flat",
            cursor="hand2",
            width=25,
            pady=10
        ).pack(pady=5)


        # Hash output
        tk.Label(
            right,
            text="SECURE HASH",
            font=("Segoe UI", 10, "bold"),
            fg="#bbbbbb",
            bg="#1b1d22"
        ).pack(
            anchor="w",
            pady=(25, 8)
        )


        self.hash_text = tk.Text(
            right,
            height=5,
            bg="#292c32",
            fg="#aaaaaa",
            insertbackground="white",
            relief="flat",
            wrap="word"
        )

        self.hash_text.pack(
            fill="x"
        )


    # =========================
    # FUNCTIONS
    # =========================

    def toggle_password(self):

        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")


    def check_strength(self):

        password = self.password_entry.get()

        if not password:
            messagebox.showwarning(
                "Warning",
                "Enter a password first."
            )
            return

        strength = password_strength(password)

        self.strength_label.config(
            text=strength
        )


    def create_hash(self):

        password = self.password_entry.get()

        if not password:
            messagebox.showwarning(
                "Warning",
                "Enter a password first."
            )
            return

        hashed = hash_password(password)

        self.hash_text.delete(
            "1.0",
            tk.END
        )

        self.hash_text.insert(
            tk.END,
            hashed
        )


    def verify(self):

        password = self.password_entry.get()

        stored_hash = self.hash_text.get(
            "1.0",
            tk.END
        ).strip()

        if not password:
            messagebox.showwarning(
                "Warning",
                "Enter a password."
            )
            return

        if not stored_hash:
            messagebox.showwarning(
                "Warning",
                "Generate or paste a stored hash."
            )
            return

        if verify_password(password, stored_hash):

            messagebox.showinfo(
                "Verification",
                "✓ Password Verified Successfully!"
            )

        else:

            messagebox.showerror(
                "Verification",
                "✗ Wrong Password!"
            )


    def generate(self):

        length = int(
            self.length_slider.get()
        )

        password = generate_password(length)

        self.generated_entry.delete(
            0,
            tk.END
        )

        self.generated_entry.insert(
            0,
            password
        )


    def copy_password(self):

        password = self.generated_entry.get()

        if not password:
            messagebox.showwarning(
                "Warning",
                "Generate a password first."
            )
            return

        pyperclip.copy(password)

        messagebox.showinfo(
            "Copied",
            "Password copied to clipboard."
        )


# =========================
# START
# =========================

if __name__ == "__main__":

    root = tk.Tk()

    app = PasswordSecurityTool(root)

    root.mainloop()
