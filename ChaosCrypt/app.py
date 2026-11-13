"""
ChaosCrypt - image encryption desktop app.
Run:  python app.py
"""
import os
import queue
import threading
from tkinter import filedialog, messagebox

import customtkinter as ctk

import imgcrypt_core as core

PREVIEW = (400, 300)        # max preview size in pixels
HIST = (400, 90)
ACCENT = "#3b82f6"

MODE_LABELS = {"AES-256-GCM": "gcm", "Chaotic (paper)": "chaotic"}
MODE_NAMES = {v: k for k, v in MODE_LABELS.items()}
MODE_INFO = {
    "gcm": "AES-256-GCM: standard, authenticated encryption.\nRecommended for real protection.",
    "chaotic": "Logistic-map scheme from the Entropy 2022 paper.\nGood for learning and research, not for secrets.",
}


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("ChaosCrypt - Image Encryption")
        self.geometry("1180x800")
        self.minsize(1050, 740)

        self.arr = None            # currently opened image (numpy HxWxC)
        self.meta = None           # metadata if the opened file is an encrypted PNG
        self.result = None         # last result array
        self.result_meta = None
        self.busy = False
        self.jobs = queue.Queue()
        self._refs = {}            # keep CTkImage objects alive

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self._build_sidebar()
        self._build_main()
        self.after(80, self._poll)

    # ------------------------------------------------------------------ UI --
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=270, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)

        ctk.CTkLabel(sb, text="ChaosCrypt", font=ctk.CTkFont(size=26, weight="bold"),
                     text_color=ACCENT).pack(padx=20, pady=(26, 0), anchor="w")
        ctk.CTkLabel(sb, text="Image encryption", text_color="gray").pack(padx=20, anchor="w")

        ctk.CTkLabel(sb, text="ALGORITHM", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray").pack(padx=20, pady=(26, 6), anchor="w")
        self.mode_btn = ctk.CTkSegmentedButton(sb, values=list(MODE_LABELS), command=self._on_mode)
        self.mode_btn.pack(padx=20, fill="x")
        self.mode_btn.set("AES-256-GCM")
        self.mode_info = ctk.CTkLabel(sb, text=MODE_INFO["gcm"], justify="left",
                                      text_color="gray", wraplength=225)
        self.mode_info.pack(padx=20, pady=(8, 0), anchor="w")

        ctk.CTkLabel(sb, text="PASSWORD", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="gray").pack(padx=20, pady=(24, 6), anchor="w")
        self.pwd = ctk.CTkEntry(sb, show="*", placeholder_text="min. 8 characters", height=36)
        self.pwd.pack(padx=20, fill="x")
        self.show_pwd = ctk.CTkCheckBox(sb, text="Show password", command=self._toggle_pwd)
        self.show_pwd.pack(padx=20, pady=(8, 0), anchor="w")

        self.btn_open = ctk.CTkButton(sb, text="Open image...", height=40, command=self.open_image)
        self.btn_open.pack(padx=20, pady=(28, 0), fill="x")
        self.btn_enc = ctk.CTkButton(sb, text="Encrypt", height=40, command=self.encrypt,
                                     fg_color="#16a34a", hover_color="#15803d")
        self.btn_enc.pack(padx=20, pady=(10, 0), fill="x")
        self.btn_dec = ctk.CTkButton(sb, text="Decrypt", height=40, command=self.decrypt,
                                     fg_color="#d97706", hover_color="#b45309")
        self.btn_dec.pack(padx=20, pady=(10, 0), fill="x")
        self.btn_save = ctk.CTkButton(sb, text="Save result as PNG...", height=40,
                                      command=self.save, fg_color="transparent",
                                      border_width=2, text_color=("gray10", "gray90"))
        self.btn_save.pack(padx=20, pady=(10, 0), fill="x")

        self.progress = ctk.CTkProgressBar(sb, mode="indeterminate")
        self.progress.pack(padx=20, pady=(26, 0), fill="x")
        self.progress.set(0)
        self.status = ctk.CTkLabel(sb, text="Open an image to start.", justify="left",
                                   wraplength=225, text_color="gray")
        self.status.pack(padx=20, pady=(8, 0), anchor="w")

        ctk.CTkOptionMenu(sb, values=["Dark", "Light", "System"],
                          command=lambda v: ctk.set_appearance_mode(v)
                          ).pack(padx=20, pady=(0, 20), fill="x", side="bottom")
        ctk.CTkLabel(sb, text="Theme").pack(padx=20, pady=(0, 4), anchor="w", side="bottom")

    def _card(self, parent, col, title):
        card = ctk.CTkFrame(parent, corner_radius=14)
        card.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 8 if col == 0 else 0))
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=15, weight="bold")
                     ).pack(padx=16, pady=(14, 8), anchor="w")
        img_label = ctk.CTkLabel(card, text="No image", width=PREVIEW[0], height=PREVIEW[1],
                                 fg_color=("gray85", "gray17"), corner_radius=10)
        img_label.pack(padx=16)
        hist_label = ctk.CTkLabel(card, text="", width=HIST[0], height=HIST[1])
        hist_label.pack(padx=16, pady=(10, 16))
        return img_label, hist_label

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        main.grid_columnconfigure((0, 1), weight=1, uniform="cards")
        main.grid_rowconfigure(1, weight=1)

        cards = ctk.CTkFrame(main, fg_color="transparent")
        cards.grid(row=0, column=0, columnspan=2, sticky="nsew")
        cards.grid_columnconfigure((0, 1), weight=1, uniform="c")
        self.in_img, self.in_hist = self._card(cards, 0, "Input")
        self.out_img, self.out_hist = self._card(cards, 1, "Result")

        box = ctk.CTkFrame(main, corner_radius=14)
        box.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(16, 0))
        ctk.CTkLabel(box, text="Security analysis", font=ctk.CTkFont(size=15, weight="bold")
                     ).pack(padx=16, pady=(14, 6), anchor="w")
        self.report = ctk.CTkTextbox(box, height=130, font=ctk.CTkFont(family="Courier", size=12))
        self.report.pack(padx=16, pady=(0, 16), fill="both", expand=True)
        self._set_report("Encrypt an image to see entropy, chi-square and correlation results.")

    # ------------------------------------------------------------- helpers --
    def _toggle_pwd(self):
        self.pwd.configure(show="" if self.show_pwd.get() else "*")

    def _on_mode(self, label):
        self.mode_info.configure(text=MODE_INFO[MODE_LABELS[label]])

    def _set_status(self, text, color="gray"):
        self.status.configure(text=text, text_color=color)

    def _set_report(self, text):
        self.report.configure(state="normal")
        self.report.delete("1.0", "end")
        self.report.insert("1.0", text)
        self.report.configure(state="disabled")

    def _set_buttons(self, state):
        for b in (self.btn_open, self.btn_enc, self.btn_dec, self.btn_save):
            b.configure(state=state)

    def _show(self, img_label, hist_label, arr):
        img = core.array_to_image(arr)
        thumb = img.copy()
        thumb.thumbnail(PREVIEW)
        ci = ctk.CTkImage(light_image=thumb, dark_image=thumb, size=thumb.size)
        img_label.configure(image=ci, text="")
        hi = core.histogram_image(arr, HIST)
        ch = ctk.CTkImage(light_image=hi, dark_image=hi, size=HIST)
        hist_label.configure(image=ch)
        self._refs[img_label] = (ci, ch)

    def _need_password(self, encrypting):
        pw = self.pwd.get()
        if not pw:
            messagebox.showwarning("Password", "Please enter a password.")
            return None
        if encrypting and len(pw) < 8:
            messagebox.showwarning("Password", "Use at least 8 characters.")
            return None
        return pw

    # --------------------------------------------------- background worker --
    def _poll(self):
        try:
            while True:
                self.jobs.get_nowait()()
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _run(self, work, done, message):
        if self.busy:
            return
        self.busy = True
        self._set_buttons("disabled")
        self.progress.start()
        self._set_status(message)

        def target():
            try:
                res, err = work(), None
            except Exception as exc:          # shown to the user below
                res, err = None, exc
            self.jobs.put(lambda: self._finish(res, err, done))

        threading.Thread(target=target, daemon=True).start()

    def _finish(self, res, err, done):
        self.busy = False
        self.progress.stop()
        self.progress.set(0)
        self._set_buttons("normal")
        if err is not None:
            self._set_status("Failed.", "#ef4444")
            if isinstance(err, core.CryptoError):
                messagebox.showerror("Error", str(err))
            else:
                messagebox.showerror("Unexpected error", f"{type(err).__name__}: {err}")
            return
        done(res)

    # ------------------------------------------------------------- actions --
    def open_image(self):
        path = filedialog.askopenfilename(
            title="Open image",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tif *.tiff *.webp"), ("All files", "*.*")])
        if not path:
            return
        try:
            self.arr, self.meta, _ = core.read_any(path)
        except Exception as exc:
            messagebox.showerror("Cannot open", f"{type(exc).__name__}: {exc}")
            return
        self._show(self.in_img, self.in_hist, self.arr)
        h, w, _ = self.arr.shape
        name = os.path.basename(path)
        if self.meta:
            self.mode_btn.set(MODE_NAMES.get(self.meta.get("mode"), "AES-256-GCM"))
            self._on_mode(self.mode_btn.get())
            self._set_status(f"{name} ({w}x{h})\nEncrypted image detected. Enter the password and press Decrypt.")
        else:
            self._set_status(f"{name} ({w}x{h})\nReady. Choose algorithm + password, then Encrypt.")

    def encrypt(self):
        if self.arr is None:
            return messagebox.showinfo("Encrypt", "Open an image first.")
        if self.meta:
            return messagebox.showinfo("Encrypt", "This image is already encrypted. Use Decrypt.")
        pw = self._need_password(True)
        if pw is None:
            return
        mode, arr = MODE_LABELS[self.mode_btn.get()], self.arr

        def work():
            cipher, meta = core.encrypt(arr, pw, mode)
            return cipher, meta, core.analyze(arr, cipher)

        def done(res):
            cipher, meta, rep = res
            self.result, self.result_meta = cipher, meta
            self._show(self.out_img, self.out_hist, cipher)
            self._set_report(core.format_report(rep))
            self._set_status("Encrypted. Save the result as PNG (never JPEG!).", "#22c55e")

        self._run(work, done, "Encrypting...")

    def decrypt(self):
        if self.arr is None or not self.meta:
            return messagebox.showinfo("Decrypt", "Open an encrypted PNG made by this app first.")
        pw = self._need_password(False)
        if pw is None:
            return
        arr, meta = self.arr, self.meta

        def work():
            return core.decrypt(arr, meta, pw)

        def done(plain):
            self.result, self.result_meta = plain, None
            self._show(self.out_img, self.out_hist, plain)
            self._set_report("Decryption successful. Integrity check passed.")
            self._set_status("Decrypted. You can save the picture.", "#22c55e")

        self._run(work, done, "Decrypting...")

    def save(self):
        if self.result is None:
            return messagebox.showinfo("Save", "Nothing to save yet.")
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image", "*.png")],
                                            initialfile="result.png")
        if not path:
            return
        try:
            core.save_png(self.result, path, self.result_meta)
        except Exception as exc:
            return messagebox.showerror("Save failed", f"{type(exc).__name__}: {exc}")
        self._set_status(f"Saved: {os.path.basename(path)}", "#22c55e")


if __name__ == "__main__":
    App().mainloop()
